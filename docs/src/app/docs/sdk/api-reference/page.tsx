import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function ApiReferencePage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">API Reference</h1>
          <Badge variant="default" className="bg-cyan-600">C/C++</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Complete documentation of all 80+ DioProcess SDK methods organized by category.
        </p>
      </div>

      <nav className="space-y-2 p-4 bg-card rounded-lg border border-border">
        <h3 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide">Quick Navigation</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
          <a href="#connection" className="text-violet-400 hover:underline">Connection</a>
          <a href="#collection" className="text-violet-400 hover:underline">Collection Control</a>
          <a href="#protection" className="text-violet-400 hover:underline">Process Protection</a>
          <a href="#callback-enum" className="text-violet-400 hover:underline">Callback Enumeration</a>
          <a href="#callback-remove" className="text-violet-400 hover:underline">Callback Removal</a>
          <a href="#callback-restore" className="text-violet-400 hover:underline">Callback Restore</a>
          <a href="#hypervisor" className="text-violet-400 hover:underline">Hypervisor Control</a>
          <a href="#hv-memory" className="text-violet-400 hover:underline">HV Memory</a>
          <a href="#hiding" className="text-violet-400 hover:underline">DKOM Hiding</a>
          <a href="#file-hiding" className="text-violet-400 hover:underline">File Hiding</a>
          <a href="#port-hiding" className="text-violet-400 hover:underline">Port Hiding</a>
          <a href="#memory-hiding" className="text-violet-400 hover:underline">Memory Hiding</a>
          <a href="#kernel-injection" className="text-violet-400 hover:underline">Kernel Injection</a>
          <a href="#early-injection" className="text-violet-400 hover:underline">Early Injection</a>
          <a href="#physical-memory" className="text-violet-400 hover:underline">Physical Memory</a>
          <a href="#vm-regions" className="text-violet-400 hover:underline">VM Regions</a>
          <a href="#ept-hooks" className="text-violet-400 hover:underline">EPT Hooks</a>
          <a href="#register-changes" className="text-violet-400 hover:underline">Register Changes</a>
          <a href="#process-kill" className="text-violet-400 hover:underline">Process Kill</a>
          <a href="#thread-control" className="text-violet-400 hover:underline">Thread Control</a>
          <a href="#system-threads" className="text-violet-400 hover:underline">System Threads</a>
          <a href="#packet-capture" className="text-violet-400 hover:underline">Packet Capture</a>
          <a href="#memory-copy" className="text-violet-400 hover:underline">Memory Copy</a>
          <a href="#configuration" className="text-violet-400 hover:underline">Configuration</a>
        </div>
      </nav>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">DioProcessSDK Class</h2>
        <p className="text-muted-foreground">
          Main SDK class that wraps driver communication.
        </p>
        <CodeBlock
          language="cpp"
          code={`class DioProcessSDK {
public:
    DioProcessSDK();
    ~DioProcessSDK();
    
    BOOL Open();
    void Close();
    BOOL IsOpen() const;
    
    // 80+ methods organized by category below
};`}
        />
      </section>

      <section id="connection" className="space-y-4">
        <h2 className="text-2xl font-bold">Connection Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">Open()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Open handle to \\.\DioProcess driver</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">Close()</td>
                <td className="py-2 px-3 font-mono text-xs">void</td>
                <td className="py-2 px-3 text-muted-foreground">Close driver handle</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">IsOpen()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Check if driver handle is valid</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="collection" className="space-y-4">
        <h2 className="text-2xl font-bold">Collection Control Methods</h2>
        <p className="text-muted-foreground">Control kernel callback event collection.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">StartCollection()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Start collecting callback events</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">StopCollection()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Stop callback event collection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">GetCollectionState()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Query whether collection is active</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RegisterCallbacks()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Register kernel callbacks (Ps, Ob, Cm)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnregisterCallbacks()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unregister all kernel callbacks</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="protection" className="space-y-4">
        <h2 className="text-2xl font-bold">Process Protection Methods</h2>
        <p className="text-muted-foreground">Manipulate kernel-level process protection (PPL/PS_PROTECTION).</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ProtectProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Apply PPL protection to process (WinTcb signer)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnprotectProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove PPL protection from process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ProtectProcessEx(ULONG pid, ProcessProtectionLevel level)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Apply specific protection level (None/Light/Full)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnableAllPrivileges(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Enable all 40 token privileges (SeDebugPrivilege, etc.)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ClearDebugFlags(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Clear anti-debug flags (DebugPort, BeingDebugged, NtGlobalFlag)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="callback-enum" className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Enumeration Methods</h2>
        <p className="text-muted-foreground">Enumerate registered kernel callbacks from various subsystems.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Output Structure</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumProcessCallbacks(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">CallbackInformation[]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumThreadCallbacks(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">CallbackInformation[]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumImageCallbacks(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">CallbackInformation[]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumObjectCallbacks(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">ObjectCallbackInformation[]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumRegistryCallbacks(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">RegistryCallbackInformation[]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnumMinifilters(buf, size, &amp;returned)</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">MinifilterInformation[]</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          All enumeration methods return ULONG count at buffer start, followed by array of structures.
        </p>
      </section>

      <section id="callback-remove" className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Removal Methods</h2>
        <p className="text-muted-foreground">Remove (NOP out) kernel callbacks by index.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RemoveProcessCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove process callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RemoveThreadCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove thread callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RemoveImageCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove image load callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RemoveObjectCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove object callback (ObRegisterCallbacks)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RemoveRegistryCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove registry callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnlinkMinifilter(LPCWSTR name)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unlink minifilter callbacks by name</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="callback-restore" className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Restore Methods</h2>
        <p className="text-muted-foreground">Restore previously removed kernel callbacks.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RestoreProcessCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Restore removed process callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RestoreThreadCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Restore removed thread callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RestoreImageCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Restore removed image callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RestoreObjectCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Restore removed object callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RestoreRegistryCallback(ULONG index)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Restore removed registry callback</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="hypervisor" className="space-y-4">
        <h2 className="text-2xl font-bold">Hypervisor Control Methods</h2>
        <p className="text-muted-foreground">Control the Ring -1 hypervisor.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvStart()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Start the hypervisor (virtualize OS)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvStop()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Stop the hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvPing(HvPingResponse*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Get hypervisor status and hook count</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvProtectProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Hide process via hypervisor EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvUnprotectProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide process from EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvHideDriver(LPCWSTR name)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Hide driver from enumeration</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvUnhideDriver(LPCWSTR name)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide driver</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvInjectShellcode(pid, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Ring -1 shellcode injection via EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvInjectDll(pid, path)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Ring -1 DLL injection via EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvInstallHooks()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Install all EPT hooks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvRemoveHooks()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove all EPT hooks</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="hv-memory" className="space-y-4">
        <h2 className="text-2xl font-bold">HV Memory Methods</h2>
        <p className="text-muted-foreground">Read/write memory via hypervisor EPT.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvReadVm(ULONG pid, ULONG64 addr, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Read virtual memory via hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HvWriteVm(ULONG pid, ULONG64 addr, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Write virtual memory via hypervisor</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="hiding" className="space-y-4">
        <h2 className="text-2xl font-bold">DKOM Hiding Methods</h2>
        <p className="text-muted-foreground">Hide processes via Direct Kernel Object Manipulation.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HideProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unlink process from ActiveProcessLinks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnhideProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Relink process to list</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumHiddenProcesses(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List currently hidden processes</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="file-hiding" className="space-y-4">
        <h2 className="text-2xl font-bold">File Hiding Methods</h2>
        <p className="text-muted-foreground">Hide files from directory enumeration.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HideFile(LPCWSTR path)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Hide file from directory listing</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnhideFile(LPCWSTR path)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide file</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumHiddenFiles(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List currently hidden files</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="port-hiding" className="space-y-4">
        <h2 className="text-2xl font-bold">Port Hiding Methods</h2>
        <p className="text-muted-foreground">Hide TCP/UDP ports from network enumeration.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HidePort(USHORT port, UCHAR proto)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Hide TCP(6) or UDP(17) port</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">UnhidePort(USHORT port, UCHAR proto)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide port</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumHiddenPorts(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List currently hidden ports</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="memory-hiding" className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Hiding Methods</h2>
        <p className="text-muted-foreground">Hide memory regions from process enumeration.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">HideMemory(ULONG pid, ULONG64 addr, ULONG size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Hide memory region from VAD enumeration</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="kernel-injection" className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel Injection Methods</h2>
        <p className="text-muted-foreground">Inject code from Ring 0 via RtlCreateUserThread.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KernelInjectShellcode(req*, resp*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 shellcode injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KernelInjectDll(req*, resp*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 DLL injection via LoadLibraryW</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KernelManualMap(req*, resp*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 manual mapping (no IAT)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="early-injection" className="space-y-4">
        <h2 className="text-2xl font-bold">Early Injection Methods</h2>
        <p className="text-muted-foreground">Inject DLLs at process creation before user code runs.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EarlyInjectArm(target, dllPath, oneShot)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Arm injection for target process name</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EarlyInjectDisarm()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Disarm early injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EarlyInjectStatus(EarlyInjectStatusResponse*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Get injection state and count</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="physical-memory" className="space-y-4">
        <h2 className="text-2xl font-bold">Physical Memory Methods</h2>
        <p className="text-muted-foreground">Direct physical memory access via MmCopyMemory.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">TranslateVa(pid, virtAddr, TranslateVaResp*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Walk CR3 page tables VA → PA</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ReadPhysical(physAddr, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Read from physical address</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">WritePhysical(physAddr, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Write to physical address</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PhysReadVm(pid, virtAddr, buf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Read via translate + physical read</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="vm-regions" className="space-y-4">
        <h2 className="text-2xl font-bold">VM Region Methods</h2>
        <p className="text-muted-foreground">Enumerate virtual memory regions.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumVmRegions(pid, buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List VM regions via VAD tree walk</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="ept-hooks" className="space-y-4">
        <h2 className="text-2xl font-bold">EPT Hook Methods</h2>
        <p className="text-muted-foreground">Install invisible execute-page hooks via Extended Page Tables.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EptHookInstall(pid, addr, patch, size, &amp;idx)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Install EPT hook with patch bytes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EptHookRemove(ULONG hookIndex)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove EPT hook by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EptHookList(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List all active EPT hooks</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="register-changes" className="space-y-4">
        <h2 className="text-2xl font-bold">Register Change Methods</h2>
        <p className="text-muted-foreground">Monitor and modify registers at specific addresses.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RegChangeInstall(pid, addr, reg, op, val, &amp;idx)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Install register change hook</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RegChangeRemove(ULONG hookIndex)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove register change by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RegChangeRemoveAll()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove all register changes</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">RegChangeList(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List all register changes</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="process-kill" className="space-y-4">
        <h2 className="text-2xl font-bold">Process Kill Methods</h2>
        <p className="text-muted-foreground">Various methods to terminate protected processes.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KillProcessTerminate(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Terminate via ZwTerminateProcess</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KillProcessUnmap(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Unmap main module sections</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">KillProcessPebCorrupt(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Corrupt PEB to crash process</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="thread-control" className="space-y-4">
        <h2 className="text-2xl font-bold">Thread Control Methods</h2>
        <p className="text-muted-foreground">Suspend, resume, and terminate threads.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">SuspendProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Suspend all threads in process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ResumeProcess(ULONG pid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Resume all threads in process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">SuspendThread(ULONG tid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Suspend single thread</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">ResumeThread(ULONG tid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Resume single thread</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">TerminateThread(ULONG tid)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Terminate thread via ZwTerminateThread</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="system-threads" className="space-y-4">
        <h2 className="text-2xl font-bold">System Thread Enumeration</h2>
        <p className="text-muted-foreground">Enumerate kernel-mode system threads.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumSystemThreads(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List system threads (PID 4)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">EnumAllKernelThreads(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List all kernel-mode threads</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="packet-capture" className="space-y-4">
        <h2 className="text-2xl font-bold">Packet Capture Methods</h2>
        <p className="text-muted-foreground">Network packet capture via NDIS filter driver.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketStartCapture(interfaceIdx)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Start capturing on interface</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketStopCapture()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Stop packet capture</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketGetPackets(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Retrieve captured packets</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketAddFilter(filterRule)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Add BPF-style packet filter</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketRemoveFilter(filterId)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Remove packet filter</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketClearFilters()</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Clear all packet filters</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketGetStats(PacketCaptureStats*)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Get capture statistics</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">PacketEnumInterfaces(buf, size, &amp;count)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">List available network interfaces</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="memory-copy" className="space-y-4">
        <h2 className="text-2xl font-bold">Memory Copy Methods</h2>
        <p className="text-muted-foreground">Read process memory via MmCopyVirtualMemory.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">CopyMemory(pid, srcAddr, dstBuf, size)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Copy memory from target process (KsDumper-style)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="configuration" className="space-y-4">
        <h2 className="text-2xl font-bold">Configuration Methods</h2>
        <p className="text-muted-foreground">Configure driver offsets for different Windows versions.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Returns</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">SetRegistryCallbackOffsets(cookie, context)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Set CM_CALLBACK offsets</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">SetEthreadOffsets(startAddr, win32Start)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Set ETHREAD field offsets</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs text-violet-400">SetThreadApiAddresses(suspend, resume, term)</td>
                <td className="py-2 px-3 font-mono text-xs">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Set thread API function addresses</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Key Structures</h2>
        <CodeBlock
          language="cpp"
          code={`// Callback information (process, thread, image)
struct CallbackInformation {
    ULONG Index;                                // Callback slot index
    ULONG64 CallbackAddress;                    // Kernel address
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];    // Driver name
};

// Object callback (ObRegisterCallbacks)
struct ObjectCallbackInformation {
    CHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    CHAR Altitude[MAX_ALTITUDE_LENGTH];
    ObjectCallbackType ObjectType;
    ObjectCallbackOperations Operations;
    ULONG64 PreOperationCallback;
    ULONG64 PostOperationCallback;
    ULONG Index;
};

// CID table entry
struct CidTableEntry {
    ULONG Id;                                   // PID or TID
    ULONG64 ObjectAddress;                      // EPROCESS or ETHREAD
    CidObjectType ObjectType;                   // Process or Thread
    ULONG ParentPid;                            // Parent/owner PID
    CHAR ProcessName[MAX_PROCESS_NAME_LENGTH];  // Image file name
};

// Hypervisor ping response
struct HvPingResponse {
    BOOLEAN IsRunning;
    BOOLEAN HooksInstalled;
    ULONG ProtectedProcessCount;
    ULONG HiddenDriverCount;
};

// Physical memory translation
struct TranslateVaResponse {
    ULONG64 PhysicalAddress;
    ULONG PageSize;
    BOOLEAN Valid;
};

// EPT hook info
struct EptHookInfo {
    ULONG ProcessId;
    ULONG64 TargetAddress;
    ULONG PatchSize;
    ULONG HookIndex;
    BOOLEAN Active;
};

// Register change info
struct RegisterChangeInfo {
    ULONG ProcessId;
    ULONG64 Address;
    RegisterType Register;
    ChangeOperation Operation;
    ULONG64 Value;
    ULONG HookIndex;
    BOOLEAN Active;
};

// Hidden port info
struct HiddenPortInfo {
    USHORT Port;
    UCHAR Protocol;      // 6 = TCP, 17 = UDP
    ULONG Index;
};

// Packet capture entry
struct PacketEntry {
    ULONG64 Timestamp;
    ULONG Length;
    UCHAR Direction;     // 0 = inbound, 1 = outbound
    BYTE Data[MAX_PACKET_SIZE];
};

// Kernel inject request/response
struct KernelInjectShellcodeRequest {
    ULONG ProcessId;
    ULONG ShellcodeSize;
    BYTE Shellcode[4096];
};

struct KernelInjectResponse {
    ULONG64 ShellcodeAddress;
    ULONG64 ModuleBase;
    ULONG64 ThreadHandle;
    BOOLEAN Success;
};

// Early injection status
struct EarlyInjectStatusResponse {
    BOOLEAN Armed;
    WCHAR TargetProcess[MAX_PATH];
    WCHAR DllPath[MAX_PATH];
    BOOLEAN OneShot;
    ULONG InjectionCount;
    ULONG LastInjectedPid;
};`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTL Codes</h2>
        <p className="text-muted-foreground">
          Direct IOCTL codes for advanced usage (grouped by category):
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Code</th>
                <th className="text-left py-2 px-3 font-semibold">Name</th>
                <th className="text-left py-2 px-3 font-semibold">Category</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x800</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_START_COLLECTION</td>
                <td className="py-2 px-3 text-xs text-cyan-400">Collection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x801</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_STOP_COLLECTION</td>
                <td className="py-2 px-3 text-xs text-cyan-400">Collection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x805</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_PROTECT_PROCESS</td>
                <td className="py-2 px-3 text-xs text-green-400">Protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x806</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_UNPROTECT_PROCESS</td>
                <td className="py-2 px-3 text-xs text-green-400">Protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x807</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_ENABLE_PRIVILEGES</td>
                <td className="py-2 px-3 text-xs text-green-400">Protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x808</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_CLEAR_DEBUG_FLAGS</td>
                <td className="py-2 px-3 text-xs text-green-400">Protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x809</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_ENUM_PROCESS_CALLBACKS</td>
                <td className="py-2 px-3 text-xs text-yellow-400">Callbacks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x80A</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_ENUM_THREAD_CALLBACKS</td>
                <td className="py-2 px-3 text-xs text-yellow-400">Callbacks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x80B</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_ENUM_IMAGE_CALLBACKS</td>
                <td className="py-2 px-3 text-xs text-yellow-400">Callbacks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x810</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_REMOVE_CALLBACK</td>
                <td className="py-2 px-3 text-xs text-yellow-400">Callbacks</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x820</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HV_START</td>
                <td className="py-2 px-3 text-xs text-violet-400">Hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x821</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HV_STOP</td>
                <td className="py-2 px-3 text-xs text-violet-400">Hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x822</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HV_PING</td>
                <td className="py-2 px-3 text-xs text-violet-400">Hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x840</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HV_INJECT_SHELLCODE</td>
                <td className="py-2 px-3 text-xs text-violet-400">Hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x841</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HV_INJECT_DLL</td>
                <td className="py-2 px-3 text-xs text-violet-400">Hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x850</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HIDE_PROCESS</td>
                <td className="py-2 px-3 text-xs text-orange-400">Hiding</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x860</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HIDE_FILE</td>
                <td className="py-2 px-3 text-xs text-orange-400">Hiding</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x870</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_HIDE_PORT</td>
                <td className="py-2 px-3 text-xs text-orange-400">Hiding</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x880</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_KERNEL_INJECT_SHELLCODE</td>
                <td className="py-2 px-3 text-xs text-red-400">Injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x881</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_KERNEL_INJECT_DLL</td>
                <td className="py-2 px-3 text-xs text-red-400">Injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x890</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_EARLY_INJECT_ARM</td>
                <td className="py-2 px-3 text-xs text-red-400">Injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8A0</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_TRANSLATE_VA</td>
                <td className="py-2 px-3 text-xs text-pink-400">Memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8A1</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_READ_PHYSICAL</td>
                <td className="py-2 px-3 text-xs text-pink-400">Memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8A2</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_WRITE_PHYSICAL</td>
                <td className="py-2 px-3 text-xs text-pink-400">Memory</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8B0</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_EPT_HOOK_INSTALL</td>
                <td className="py-2 px-3 text-xs text-violet-400">EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8B1</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_EPT_HOOK_REMOVE</td>
                <td className="py-2 px-3 text-xs text-violet-400">EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8C0</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_REG_CHANGE_INSTALL</td>
                <td className="py-2 px-3 text-xs text-violet-400">EPT</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x900</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_PACKET_START_CAPTURE</td>
                <td className="py-2 px-3 text-xs text-blue-400">Network</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x908</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_KILL_PROCESS</td>
                <td className="py-2 px-3 text-xs text-red-400">Control</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          Full IOCTL codes available in <code>DioProcessSDK.h</code> (100+ codes).
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Error Handling</h2>
        <CodeBlock
          language="cpp"
          code={`// All methods return BOOL/bool
if (!sdk.ProtectProcess(pid)) {
    DWORD error = GetLastError();
    
    // Common error codes:
    // ERROR_ACCESS_DENIED (5)     - Not admin
    // ERROR_FILE_NOT_FOUND (2)    - Driver not loaded
    // ERROR_INVALID_PARAMETER (87)- Invalid PID
    // ERROR_NOT_SUPPORTED (50)    - Unsupported Windows version
}`}
        />
      </section>
    </div>
  );
}
