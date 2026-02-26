import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function RegistryCallbacksPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Registry Callbacks</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate, remove, and restore registry notification callbacks registered via 
          CmRegisterCallbackEx.
        </p>
      </div>

      <WarningBox variant="warning" title="Security Research Only">
        Removing registry callbacks may affect system stability and security product 
        functionality. Use only for authorized research on test systems.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Registry callbacks allow kernel drivers to monitor and intercept registry operations. 
          EDR/AV products use these to detect malicious registry modifications. DioProcess can 
          enumerate these callbacks and optionally remove/restore them.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">RegistryCallbackInfo Structure</h2>
        <CodeBlock
          language="rust"
          filename="crates/callback/src/types.rs"
          code={`pub struct RegistryCallbackInfo {
    pub index: u32,              // Callback slot index
    pub callback_address: u64,   // Callback function address
    pub cookie: u64,             // Registration cookie (for unregister)
    pub altitude: String,        // Callback altitude (priority string)
    pub module_name: String,     // Driver module name
}

// Registry operations monitored by callbacks
pub enum RegNotifyClass {
    RegNtPreDeleteKey,
    RegNtPreSetValueKey,
    RegNtPreDeleteValueKey,
    RegNtPreSetInformationKey,
    RegNtPreRenameKey,
    RegNtPreEnumerateKey,
    RegNtPreEnumerateValueKey,
    RegNtPreQueryKey,
    RegNtPreQueryValueKey,
    RegNtPreCreateKey,
    RegNtPreCreateKeyEx,
    RegNtPostCreateKey,
    RegNtPostCreateKeyEx,
    // ... 30+ operation types
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <CodeBlock
          language="cpp"
          filename="Algorithm"
          code={`// Enumeration: Walk the CmCallbackListHead linked list
NTSTATUS EnumerateRegistryCallbacks(PREG_CALLBACK_INFO* Callbacks, PULONG Count) {
    // 1. Find CmCallbackListHead via signature scanning in CM (Configuration Manager)
    PLIST_ENTRY CallbackListHead = FindCmCallbackListHead();
    
    // 2. Walk the doubly-linked list
    PLIST_ENTRY Entry = CallbackListHead->Flink;
    while (Entry != CallbackListHead) {
        // 3. Get the callback registration structure
        PCM_CALLBACK_CONTEXT_BLOCK Context = CONTAINING_RECORD(
            Entry,
            CM_CALLBACK_CONTEXT_BLOCK,
            CallbackListEntry
        );
        
        Info->Index = Index++;
        Info->CallbackAddress = (ULONG64)Context->Function;
        Info->Cookie = (ULONG64)Context->Cookie;
        Info->Altitude = Context->Altitude.Buffer;
        Info->ModuleName = GetModuleFromAddress(Context->Function);
        
        Entry = Entry->Flink;
    }
    
    return STATUS_SUCCESS;
}

// Remove: Unlink from list, save for restore
NTSTATUS RemoveRegistryCallback(ULONG Index) {
    // Find callback by index
    // Save original Flink/Blink
    // Unlink from list: Prev->Flink = Entry->Flink; Next->Blink = Entry->Blink
    return STATUS_SUCCESS;
}

// Restore: Re-link saved entry
NTSTATUS RestoreRegistryCallback(ULONG Index) {
    // Use saved Flink/Blink to reinsert at original position
    return STATUS_SUCCESS;
}`}
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
                <td className="py-2 px-3 font-mono text-xs">ENUM_REGISTRY_CALLBACKS</td>
                <td className="py-2 px-3">0x0022204C</td>
                <td className="py-2 px-3 text-muted-foreground">Enumerate all registry callbacks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">REMOVE_REGISTRY_CALLBACK</td>
                <td className="py-2 px-3">0x00222050</td>
                <td className="py-2 px-3 text-muted-foreground">Remove callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">RESTORE_REGISTRY_CALLBACK</td>
                <td className="py-2 px-3">0x00222054</td>
                <td className="py-2 px-3 text-muted-foreground">Restore previously removed callback</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Altitude System</h2>
        <p className="text-muted-foreground">
          Like minifilters, registry callbacks use an altitude string to determine call order. 
          Higher altitudes are called first (see the callback before lower-altitude callbacks).
        </p>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <p className="text-sm text-muted-foreground">
            <strong>Example altitudes:</strong><br />
            &quot;389000&quot; (high priority, security product)<br />
            &quot;320000&quot; (medium priority, AV)<br />
            &quot;200000&quot; (lower priority, monitoring)
          </p>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Features</h2>
        <p className="text-muted-foreground">
          Registry callbacks are displayed in the Callback Enumeration tab alongside process, 
          thread, image, and object callbacks:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Callback table</strong> — Index, Callback Address, Altitude, Module</li>
          <li>• <strong>Sorting</strong> — By altitude (descending) or module name</li>
          <li>• <strong>Search filter</strong> — Filter by module name or altitude</li>
          <li>• <strong>Context menu</strong> — Copy Address, Remove Callback, Restore Callback</li>
          <li>• <strong>Remove status</strong> — Visual indicator for removed callbacks</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Registry Operations Monitored</h2>
        <p className="text-muted-foreground">
          Callbacks receive notifications for these registry operations:
        </p>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">Key Operations</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• CreateKey / CreateKeyEx</li>
              <li>• OpenKey / OpenKeyEx</li>
              <li>• DeleteKey</li>
              <li>• RenameKey</li>
              <li>• EnumerateKey</li>
              <li>• QueryKey</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">Value Operations</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• SetValueKey</li>
              <li>• DeleteValueKey</li>
              <li>• QueryValueKey</li>
              <li>• EnumerateValueKey</li>
              <li>• QueryMultipleValueKey</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Identify which drivers are monitoring registry activity</li>
          <li>• Temporarily disable registry monitoring for research</li>
          <li>• Analyze how security products use registry callbacks</li>
          <li>• Test registry-based persistence detection</li>
          <li>• Forensic analysis of active registry monitors</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Related Topics</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <a href="/docs/kernel/callback-enumeration" className="text-violet hover:underline">Callback Enumeration</a> — Process, thread, image callbacks</li>
          <li>• <a href="/docs/kernel/system-events" className="text-violet hover:underline">System Events</a> — Real-time registry event capture</li>
        </ul>
      </section>
    </div>
  );
}
