import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function ServiceManagementPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Service Management</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate, control, and manage Windows services via the Service Control Manager (SCM).
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The Services tab provides complete Windows service management, allowing you to enumerate 
          all installed services, start/stop them, and create or delete service entries. This is 
          implemented in the <code className="text-violet">service</code> crate.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Service Enumeration</h3>
            <p className="text-sm text-muted-foreground">
              Lists all services with their name, display name, status (Running/Stopped/Pending), 
              start type (Auto/Manual/Disabled), binary path, description, and PID (if running).
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Service Control</h3>
            <p className="text-sm text-muted-foreground">
              Start and stop services directly from the UI. Status updates reflect in real-time.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Service Creation</h3>
            <p className="text-sm text-muted-foreground">
              Create new service entries with custom name, display name, binary path, and start type.
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Service Deletion</h3>
            <p className="text-sm text-muted-foreground">
              Remove service entries from the system (requires service to be stopped first).
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">ServiceInfo Structure</h2>
        <p className="text-muted-foreground">
          Each service is represented by the following structure:
        </p>
        <CodeBlock
          language="rust"
          filename="crates/service/src/lib.rs"
          code={`pub struct ServiceInfo {
    pub name: String,           // Internal service name
    pub display_name: String,   // Human-readable name
    pub status: ServiceStatus,  // Running, Stopped, StartPending, etc.
    pub start_type: StartType,  // Auto, Manual, Disabled, Boot, System
    pub binary_path: String,    // Path to service executable
    pub description: String,    // Service description
    pub pid: Option<u32>,       // Process ID if running
}

pub enum ServiceStatus {
    Running,
    Stopped,
    StartPending,
    StopPending,
    ContinuePending,
    PausePending,
    Paused,
}

pub enum StartType {
    Boot,       // Loaded by boot loader
    System,     // Started by IoInitSystem
    Auto,       // Started automatically at boot
    Manual,     // Started on demand
    Disabled,   // Cannot be started
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">API Functions</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Function</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">enumerate_services()</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Returns <code>Vec&lt;ServiceInfo&gt;</code> of all installed services
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">start_service(name)</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Starts a stopped service
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">stop_service(name)</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Stops a running service
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">create_service(name, display, path, start_type)</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Creates a new service entry in SCM
                </td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet">delete_service(name)</td>
                <td className="py-2 px-3 text-muted-foreground">
                  Removes a service entry (must be stopped)
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation Details</h2>
        <p className="text-muted-foreground">
          Service management uses the Windows Service Control Manager API:
        </p>
        <CodeBlock
          language="rust"
          filename="Algorithm"
          code={`// Enumeration
1. OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE)
2. EnumServicesStatusExW() with SERVICE_WIN32 | SERVICE_DRIVER
3. For each service:
   - OpenServiceW() with SERVICE_QUERY_CONFIG
   - QueryServiceConfigW() for binary path and start type
   - QueryServiceConfig2W(SERVICE_CONFIG_DESCRIPTION) for description
   - CloseServiceHandle()
4. CloseServiceHandle(scm)

// Start/Stop
1. OpenSCManagerW() with SC_MANAGER_CONNECT
2. OpenServiceW(name) with SERVICE_START or SERVICE_STOP
3. StartServiceW() or ControlService(SERVICE_CONTROL_STOP)
4. CloseServiceHandle()

// Create
1. OpenSCManagerW() with SC_MANAGER_CREATE_SERVICE
2. CreateServiceW(name, display, SERVICE_WIN32_OWN_PROCESS, start_type, ...)
3. CloseServiceHandle()

// Delete
1. OpenServiceW() with DELETE
2. DeleteService()
3. CloseServiceHandle()`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Search filter</strong> — Filter services by name, display name, or binary path</li>
          <li>• <strong>Sorting</strong> — Click column headers to sort ascending/descending</li>
          <li>• <strong>Context menu</strong> — Right-click for Start, Stop, Delete options</li>
          <li>• <strong>Create Service dialog</strong> — Modal for creating new services</li>
          <li>• <strong>CSV export</strong> — Export current filtered list to CSV</li>
          <li>• <strong>Auto-refresh</strong> — Service status updates every 3 seconds</li>
          <li>• <strong>Keyboard shortcuts</strong> — F5 (refresh), Escape (close menu)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Enumerate and analyze installed security products (AV/EDR services)</li>
          <li>• Start/stop services for debugging and testing</li>
          <li>• Create kernel driver services programmatically</li>
          <li>• Identify suspicious or malicious services by binary path</li>
          <li>• Monitor service PIDs for further analysis in Process tab</li>
        </ul>
      </section>
    </div>
  );
}
