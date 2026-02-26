import { Badge } from "@/components/ui/badge";

export default function SystemEventsPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">System Events</h1>
          <Badge variant="outline" className="border-yellow-500/30 text-yellow-500">Experimental</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Real-time kernel event capture via WDM driver with SQLite persistence.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Event Types</h2>
        <p className="text-muted-foreground">17 event types across 5 categories:</p>
        
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Category</th>
                <th className="text-left py-3 px-4 font-semibold">Events</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><Badge className="bg-green-500/20 text-green-400">Process</Badge></td>
                <td className="py-3 px-4 text-muted-foreground">ProcessCreate, ProcessExit</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><Badge className="bg-blue-500/20 text-blue-400">Thread</Badge></td>
                <td className="py-3 px-4 text-muted-foreground">ThreadCreate, ThreadExit</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><Badge className="bg-purple-500/20 text-purple-400">Image</Badge></td>
                <td className="py-3 px-4 text-muted-foreground">ImageLoad (DLL/EXE loading)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><Badge className="bg-pink-500/20 text-pink-400">Handle</Badge></td>
                <td className="py-3 px-4 text-muted-foreground">ProcessHandleCreate, ProcessHandleDuplicate, ThreadHandleCreate, ThreadHandleDuplicate</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4"><Badge className="bg-cyan-500/20 text-cyan-400">Registry</Badge></td>
                <td className="py-3 px-4 text-muted-foreground">RegistryCreate, RegistryOpen, RegistrySetValue, RegistryDeleteKey, RegistryDeleteValue, RegistryRenameKey, RegistryQueryValue</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Storage</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Database</strong> — <code>%LOCALAPPDATA%\DioProcess\events.db</code></li>
          <li>• <strong>Engine</strong> — SQLite with WAL mode for concurrent access</li>
          <li>• <strong>Batched writes</strong> — 500 events or 100ms flush interval</li>
          <li>• <strong>Retention</strong> — 24-hour auto-cleanup (runs hourly)</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Event table</strong> — Time, Type, PID, Process Name, Details</li>
          <li>• <strong>Pagination</strong> — 500 events per page with navigation</li>
          <li>• <strong>Category filter</strong> — Process, Thread, Image, Handle, Registry</li>
          <li>• <strong>Type filter</strong> — Individual event types</li>
          <li>• <strong>Search filter</strong> — PID, process name, command line, image name, registry key</li>
          <li>• <strong>Auto-refresh</strong> — 1-second polling when driver loaded</li>
          <li>• <strong>Color coding</strong> — Visual distinction by event type</li>
          <li>• <strong>CSV export</strong> — Export current page</li>
          <li>• <strong>Clear all</strong> — Delete all events from database</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Event Details</h2>
        
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Process Events</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• PID, Parent PID</li>
              <li>• Command line</li>
              <li>• Creating process ID</li>
              <li>• Exit code (for exit events)</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Image Load Events</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Image base address</li>
              <li>• Image size</li>
              <li>• Full image path</li>
              <li>• System/Kernel image flags</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Handle Events</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Source process/thread ID</li>
              <li>• Target process/thread ID</li>
              <li>• Desired/Granted access</li>
              <li>• Kernel handle flag</li>
            </ul>
          </div>
          
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Registry Events</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Key name</li>
              <li>• Value name (if applicable)</li>
              <li>• Operation type</li>
              <li>• Status code</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel Callbacks Used</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <code className="text-violet">PsSetCreateProcessNotifyRoutineEx</code> — Process events</li>
          <li>• <code className="text-violet">PsSetCreateThreadNotifyRoutine</code> — Thread events</li>
          <li>• <code className="text-violet">PsSetLoadImageNotifyRoutine</code> — Image load events</li>
          <li>• <code className="text-violet">ObRegisterCallbacks</code> — Handle operation events</li>
          <li>• <code className="text-violet">CmRegisterCallbackEx</code> — Registry events</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Ensure the kernel driver is loaded</li>
          <li>Navigate to <strong>System Events</strong> tab</li>
          <li>Events will stream in automatically</li>
          <li>Use filters to focus on specific event types</li>
          <li>Click on events for detailed information</li>
        </ol>
      </section>
    </div>
  );
}
