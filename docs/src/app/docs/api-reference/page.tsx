import { Badge } from "@/components/ui/badge";

export default function ApiReferencePage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">API Reference</h1>
        <p className="text-lg text-muted-foreground">
          Complete reference for IOCTLs, structures, and technical details.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Driver IOCTLs</h2>
        <p className="text-muted-foreground">
          All IOCTLs use <code>METHOD_BUFFERED</code> and <code>FILE_ANY_ACCESS</code>.
        </p>

        <div className="space-y-6">
          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Event Collection
              <Badge variant="outline">0x800-0x804</Badge>
            </h3>
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
                    <td className="py-2 px-3 font-mono text-xs">START_COLLECTION</td>
                    <td className="py-2 px-3">0x800</td>
                    <td className="py-2 px-3 text-muted-foreground">Start event collection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">STOP_COLLECTION</td>
                    <td className="py-2 px-3">0x801</td>
                    <td className="py-2 px-3 text-muted-foreground">Stop event collection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">GET_COLLECTION_STATE</td>
                    <td className="py-2 px-3">0x802</td>
                    <td className="py-2 px-3 text-muted-foreground">Get collection state</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REGISTER_CALLBACKS</td>
                    <td className="py-2 px-3">0x803</td>
                    <td className="py-2 px-3 text-muted-foreground">Register kernel callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">UNREGISTER_CALLBACKS</td>
                    <td className="py-2 px-3">0x804</td>
                    <td className="py-2 px-3 text-muted-foreground">Unregister kernel callbacks</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Security Research
              <Badge variant="outline">0x805-0x808</Badge>
            </h3>
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
                    <td className="py-2 px-3 font-mono text-xs">PROTECT_PROCESS</td>
                    <td className="py-2 px-3">0x805</td>
                    <td className="py-2 px-3 text-muted-foreground">Apply PPL protection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">UNPROTECT_PROCESS</td>
                    <td className="py-2 px-3">0x806</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove PPL protection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENABLE_PRIVILEGES</td>
                    <td className="py-2 px-3">0x807</td>
                    <td className="py-2 px-3 text-muted-foreground">Enable all token privileges</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">CLEAR_DEBUG_FLAGS</td>
                    <td className="py-2 px-3">0x808</td>
                    <td className="py-2 px-3 text-muted-foreground">Clear debug indicators</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Callback Enumeration
              <Badge variant="outline">0x809-0x81F</Badge>
            </h3>
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
                    <td className="py-2 px-3 font-mono text-xs">ENUM_PROCESS_CALLBACKS</td>
                    <td className="py-2 px-3">0x809</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate process callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_THREAD_CALLBACKS</td>
                    <td className="py-2 px-3">0x80A</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate thread callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_IMAGE_CALLBACKS</td>
                    <td className="py-2 px-3">0x80B</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate image load callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_PSPCIDTABLE</td>
                    <td className="py-2 px-3">0x80F</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate PspCidTable</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_OBJECT_CALLBACKS</td>
                    <td className="py-2 px-3">0x810</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate object callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_MINIFILTERS</td>
                    <td className="py-2 px-3">0x811</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate minifilters</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_REGISTRY_CALLBACKS</td>
                    <td className="py-2 px-3">0x81E</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate registry callbacks</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Hypervisor
              <Badge variant="destructive">0x820-0x844</Badge>
            </h3>
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
                    <td className="py-2 px-3 font-mono text-xs">HV_START</td>
                    <td className="py-2 px-3">0x820</td>
                    <td className="py-2 px-3 text-muted-foreground">Start hypervisor</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_STOP</td>
                    <td className="py-2 px-3">0x821</td>
                    <td className="py-2 px-3 text-muted-foreground">Stop hypervisor</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_PING</td>
                    <td className="py-2 px-3">0x822</td>
                    <td className="py-2 px-3 text-muted-foreground">Check if hypervisor running</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_PROTECT_PROCESS</td>
                    <td className="py-2 px-3">0x830</td>
                    <td className="py-2 px-3 text-muted-foreground">Hide process via EPT</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_HIDE_DRIVER</td>
                    <td className="py-2 px-3">0x834</td>
                    <td className="py-2 px-3 text-muted-foreground">Hide driver via EPT</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_INJECT_SHELLCODE</td>
                    <td className="py-2 px-3">0x840</td>
                    <td className="py-2 px-3 text-muted-foreground">Ring -1 shellcode injection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_INJECT_DLL</td>
                    <td className="py-2 px-3">0x841</td>
                    <td className="py-2 px-3 text-muted-foreground">Ring -1 DLL injection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_READ_VM</td>
                    <td className="py-2 px-3">0x842</td>
                    <td className="py-2 px-3 text-muted-foreground">Read virtual memory via HV</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HV_WRITE_VM</td>
                    <td className="py-2 px-3">0x843</td>
                    <td className="py-2 px-3 text-muted-foreground">Write virtual memory via HV</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Kernel Injection
              <Badge variant="outline">0x80C-0x80E</Badge>
            </h3>
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
                    <td className="py-2 px-3 font-mono text-xs">KERNEL_INJECT_SHELLCODE</td>
                    <td className="py-2 px-3">0x80C</td>
                    <td className="py-2 px-3 text-muted-foreground">Kernel shellcode injection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">KERNEL_INJECT_DLL</td>
                    <td className="py-2 px-3">0x80D</td>
                    <td className="py-2 px-3 text-muted-foreground">Kernel DLL injection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">KERNEL_MANUAL_MAP</td>
                    <td className="py-2 px-3">0x80E</td>
                    <td className="py-2 px-3 text-muted-foreground">Kernel manual map injection</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Key Structures</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">TargetProcessRequest</h3>
            <p className="text-sm text-muted-foreground mb-2">Used for process-targeted operations</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct TargetProcessRequest {
    ULONG ProcessId;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">CallbackInformation</h3>
            <p className="text-sm text-muted-foreground mb-2">Returned by callback enumeration</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct CallbackInformation {
    CHAR ModuleName[256];
    ULONG64 CallbackAddress;
    ULONG64 ModuleBase;
    ULONG64 ModuleOffset;
    ULONG Index;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">CidEntry</h3>
            <p className="text-sm text-muted-foreground mb-2">PspCidTable enumeration result</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct CidEntry {
    ULONG Id;              // PID or TID
    ULONG64 ObjectAddress; // EPROCESS or ETHREAD
    CidObjectType Type;    // Process or Thread
    ULONG ParentPid;
    CHAR ProcessName[16];
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">HvInjectResult</h3>
            <p className="text-sm text-muted-foreground mb-2">Ring -1 shellcode injection result</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct HvInjectResult {
    ULONG64 bytes_written;
    ULONG64 thread_handle;
    ULONG64 shellcode_address;
    BOOLEAN success;
};`}</pre>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Rust Crate Functions</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">callback crate</h3>
            <ul className="text-sm text-muted-foreground space-y-1 font-mono">
              <li>• is_driver_loaded() -&gt; bool</li>
              <li>• protect_process(pid) -&gt; Result</li>
              <li>• unprotect_process(pid) -&gt; Result</li>
              <li>• enable_all_privileges(pid) -&gt; Result</li>
              <li>• clear_debug_flags(pid) -&gt; Result</li>
              <li>• enumerate_process_callbacks() -&gt; Result&lt;Vec&lt;CallbackInfo&gt;&gt;</li>
              <li>• enumerate_pspcidtable() -&gt; Result&lt;Vec&lt;CidEntry&gt;&gt;</li>
              <li>• hv_inject_shellcode(pid, &amp;[u8]) -&gt; Result&lt;HvInjectResult&gt;</li>
              <li>• hv_inject_dll(pid, &amp;str) -&gt; Result&lt;HvInjectDllResult&gt;</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">misc crate</h3>
            <ul className="text-sm text-muted-foreground space-y-1 font-mono">
              <li>• inject_dll(pid, path) -&gt; Result</li>
              <li>• inject_dll_manual_map(pid, path) -&gt; Result</li>
              <li>• inject_shellcode_classic(pid, path) -&gt; Result</li>
              <li>• inject_shellcode_threadless(pid, path, dll, func) -&gt; Result</li>
              <li>• hollow_process(host, payload) -&gt; Result</li>
              <li>• ghost_process(payload) -&gt; Result</li>
              <li>• steal_token(pid, exe, args) -&gt; Result</li>
              <li>• scan_process_hooks(pid) -&gt; Result&lt;Vec&lt;HookInfo&gt;&gt;</li>
              <li>• unhook_dll_remote(pid, dll, base) -&gt; Result</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
