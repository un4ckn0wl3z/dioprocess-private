import { Badge } from "@/components/ui/badge";

export default function CallbackEnumerationPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Callback Enumeration</h1>
        <p className="text-lg text-muted-foreground">
          Enumerate registered kernel callbacks to identify EDR/AV hooks and security product registrations.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Types</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Process Callbacks</h3>
              <Badge variant="outline">PsSetCreateProcessNotifyRoutineEx</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Registered by AV/EDR to monitor process creation and termination.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Thread Callbacks</h3>
              <Badge variant="outline">PsSetCreateThreadNotifyRoutine</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Monitor thread creation across all processes.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Image Load Callbacks</h3>
              <Badge variant="outline">PsSetLoadImageNotifyRoutine</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Monitor DLL/EXE loading — commonly used for injection detection.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Object Callbacks</h3>
              <Badge variant="outline">ObRegisterCallbacks</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Monitor handle operations (create/duplicate) for process and thread handles. 
              Shows pre/post operation callbacks, altitude, and monitored operations.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Registry Callbacks</h3>
              <Badge variant="outline">CmRegisterCallbackEx</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              Monitor registry operations (create, open, set, delete, rename, query).
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Information</h2>
        <p className="text-muted-foreground">
          For each callback, the driver returns:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Index</strong> — Callback slot index (0-63)</li>
          <li>• <strong>Callback Address</strong> — Kernel address of the callback function</li>
          <li>• <strong>Module Name</strong> — Driver that registered the callback (e.g., WdFilter.sys)</li>
          <li>• <strong>Module Base</strong> — Base address of the owning module</li>
          <li>• <strong>Offset</strong> — RVA within the module</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Object Callback Details</h2>
        <p className="text-muted-foreground">
          Object callbacks provide additional information:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Altitude</strong> — Callback priority (higher = called first)</li>
          <li>• <strong>Pre-Operation Callback</strong> — Called before handle operation</li>
          <li>• <strong>Post-Operation Callback</strong> — Called after handle operation</li>
          <li>• <strong>Object Type</strong> — Process or Thread</li>
          <li>• <strong>Operations</strong> — Handle Create, Handle Duplicate, or both</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Removal</h2>
        <p className="text-muted-foreground">
          Callbacks can be removed or restored via context menu:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Remove Callback</strong> — Unregister the callback (zeros the slot)</li>
          <li>• <strong>Restore Callback</strong> — Re-register a previously removed callback</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Navigate to <strong>Kernel Enumeration</strong> tab</li>
          <li>Select <strong>Callback Enumeration</strong> sub-tab</li>
          <li>Click callback type buttons (Process, Thread, Image, Object, Registry)</li>
          <li>Use search filter to find specific modules or addresses</li>
          <li>Right-click for context menu actions</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Common EDR/AV Modules</h2>
        <div className="flex flex-wrap gap-2">
          {[
            "WdFilter.sys (Windows Defender)",
            "SentinelMonitor.sys",
            "CarbonBlackK.sys",
            "esensor.sys (ESET)",
            "mfeaskm.sys (McAfee)",
            "symefasi.sys (Symantec)",
            "CyOptics.sys (Cylance)",
            "csagent.sys (CrowdStrike)",
          ].map((module) => (
            <Badge key={module} variant="secondary" className="text-xs">
              {module}
            </Badge>
          ))}
        </div>
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
                <td className="py-3 px-4 font-mono">ENUM_PROCESS_CALLBACKS</td>
                <td className="py-3 px-4">0x809</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">ENUM_THREAD_CALLBACKS</td>
                <td className="py-3 px-4">0x80A</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">ENUM_IMAGE_CALLBACKS</td>
                <td className="py-3 px-4">0x80B</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">ENUM_OBJECT_CALLBACKS</td>
                <td className="py-3 px-4">0x810</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono">ENUM_REGISTRY_CALLBACKS</td>
                <td className="py-3 px-4">0x81E</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
