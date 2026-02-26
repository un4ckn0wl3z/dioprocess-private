import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Download } from "lucide-react";

export default function ApiReferencePage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">API Reference</h1>
        <p className="text-lg text-muted-foreground">
          Complete reference for IOCTLs, structures, and the DioProcessSDK C++ class.
        </p>
        <div className="mt-4 p-4 rounded-lg border border-violet/30 bg-violet/5 flex items-center justify-between gap-4">
          <p className="text-sm">
            <strong>SDK Header:</strong> <code className="text-violet">sdk/DioProcessSDK.h</code> - Single header-only SDK with 90+ IOCTLs, 70+ structures, and 60+ wrapper functions.
          </p>
          <div className="flex gap-2 shrink-0">
            <a href="/DioProcessSDK.h" download="DioProcessSDK.h">
              <Button variant="outline" size="sm" className="gap-2">
                <Download className="h-4 w-4" />
                SDK Header
              </Button>
            </a>
            <a href="/hello_world.cpp" download="hello_world.cpp">
              <Button variant="outline" size="sm" className="gap-2">
                <Download className="h-4 w-4" />
                Example
              </Button>
            </a>
          </div>
        </div>
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

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Callback Removal & Restore
              <Badge variant="outline">0x812-0x81D</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">REMOVE_PROCESS_CALLBACK</td>
                    <td className="py-2 px-3">0x812</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove process callback by index</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REMOVE_THREAD_CALLBACK</td>
                    <td className="py-2 px-3">0x814</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove thread callback by index</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REMOVE_IMAGE_CALLBACK</td>
                    <td className="py-2 px-3">0x815</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove image callback by index</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REMOVE_OBJECT_CALLBACK</td>
                    <td className="py-2 px-3">0x816</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove object callback</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">UNLINK_MINIFILTER</td>
                    <td className="py-2 px-3">0x817</td>
                    <td className="py-2 px-3 text-muted-foreground">Unlink minifilter callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">RESTORE_*_CALLBACK</td>
                    <td className="py-2 px-3">0x819-0x81D</td>
                    <td className="py-2 px-3 text-muted-foreground">Restore removed callbacks</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REMOVE_REGISTRY_CALLBACK</td>
                    <td className="py-2 px-3">0x81F</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove registry callback</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Early Injection
              <Badge variant="outline">0x850-0x852</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">EARLY_INJECT_ARM</td>
                    <td className="py-2 px-3">0x850</td>
                    <td className="py-2 px-3 text-muted-foreground">Arm early injection for process</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">EARLY_INJECT_DISARM</td>
                    <td className="py-2 px-3">0x851</td>
                    <td className="py-2 px-3 text-muted-foreground">Disarm early injection</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">EARLY_INJECT_STATUS</td>
                    <td className="py-2 px-3">0x852</td>
                    <td className="py-2 px-3 text-muted-foreground">Get early injection status</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Hiding Features
              <Badge variant="secondary">0x870-0x8A2</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">FILEHIDE_HIDE/UNHIDE/LIST</td>
                    <td className="py-2 px-3">0x870-0x872</td>
                    <td className="py-2 px-3 text-muted-foreground">Hide files via minifilter</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PROCESS_HIDE/UNHIDE/LIST</td>
                    <td className="py-2 px-3">0x880-0x882</td>
                    <td className="py-2 px-3 text-muted-foreground">DKOM process hiding</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PORT_HIDE/UNHIDE/LIST</td>
                    <td className="py-2 px-3">0x8A0-0x8A2</td>
                    <td className="py-2 px-3 text-muted-foreground">NSI port hiding</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Physical Memory & VA Translation
              <Badge variant="secondary">0x890-0x894</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">TRANSLATE_VA</td>
                    <td className="py-2 px-3">0x890</td>
                    <td className="py-2 px-3 text-muted-foreground">4-level page table walk</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">READ_PHYSICAL</td>
                    <td className="py-2 px-3">0x891</td>
                    <td className="py-2 px-3 text-muted-foreground">Read physical memory</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">WRITE_PHYSICAL</td>
                    <td className="py-2 px-3">0x892</td>
                    <td className="py-2 px-3 text-muted-foreground">Write physical memory</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PHYS_READ_VM</td>
                    <td className="py-2 px-3">0x893</td>
                    <td className="py-2 px-3 text-muted-foreground">Bulk VM read via CR3 walk (64KB)</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_VM_REGIONS</td>
                    <td className="py-2 px-3">0x894</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate VM regions (kernel-side)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              EPT Hooks & Register Changes
              <Badge variant="destructive">0x8B0-0x8C3</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">EPT_HOOK_INSTALL</td>
                    <td className="py-2 px-3">0x8B0</td>
                    <td className="py-2 px-3 text-muted-foreground">Install EPT split-page hook</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">EPT_HOOK_REMOVE</td>
                    <td className="py-2 px-3">0x8B1</td>
                    <td className="py-2 px-3 text-muted-foreground">Remove EPT hook</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">EPT_HOOK_INSTALL_DETOUR</td>
                    <td className="py-2 px-3">0x8B3</td>
                    <td className="py-2 px-3 text-muted-foreground">Install EPT detour with code cave</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">REG_CHANGE_INSTALL</td>
                    <td className="py-2 px-3">0x8C0</td>
                    <td className="py-2 px-3 text-muted-foreground">Modify registers at RIP via EPT+MTF</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">HIDE_MEMORY</td>
                    <td className="py-2 px-3">0x8D0</td>
                    <td className="py-2 px-3 text-muted-foreground">Hide memory protection via MMPFN</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Process Control & Kill
              <Badge variant="outline">0x8E0-0x8FA</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">KILL_TERMINATE</td>
                    <td className="py-2 px-3">0x8E0</td>
                    <td className="py-2 px-3 text-muted-foreground">ZwTerminateProcess</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">KILL_UNMAP</td>
                    <td className="py-2 px-3">0x8E1</td>
                    <td className="py-2 px-3 text-muted-foreground">Unmap process memory</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">KILL_PEB_CORRUPT</td>
                    <td className="py-2 px-3">0x8E2</td>
                    <td className="py-2 px-3 text-muted-foreground">Corrupt PEB to crash process</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">SUSPEND/RESUME_PROCESS</td>
                    <td className="py-2 px-3">0x8F1-0x8F2</td>
                    <td className="py-2 px-3 text-muted-foreground">Suspend/resume process</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">SUSPEND/RESUME/TERMINATE_THREAD</td>
                    <td className="py-2 px-3">0x8F4-0x8F6</td>
                    <td className="py-2 px-3 text-muted-foreground">Thread control</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_SYSTEM_THREADS</td>
                    <td className="py-2 px-3">0x8F7</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate system threads</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">ENUM_ALL_KERNEL_THREADS</td>
                    <td className="py-2 px-3">0x8F9</td>
                    <td className="py-2 px-3 text-muted-foreground">Enumerate all kernel threads</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
              Packet Capture (WFP)
              <Badge variant="outline">0x900-0x908</Badge>
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
                    <td className="py-2 px-3 font-mono text-xs">PACKET_START_CAPTURE</td>
                    <td className="py-2 px-3">0x900</td>
                    <td className="py-2 px-3 text-muted-foreground">Start packet capture for PID</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PACKET_STOP_CAPTURE</td>
                    <td className="py-2 px-3">0x901</td>
                    <td className="py-2 px-3 text-muted-foreground">Stop packet capture</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PACKET_GET_PACKETS</td>
                    <td className="py-2 px-3">0x902</td>
                    <td className="py-2 px-3 text-muted-foreground">Retrieve captured packets</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PACKET_INJECT</td>
                    <td className="py-2 px-3">0x903</td>
                    <td className="py-2 px-3 text-muted-foreground">Inject packet</td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-2 px-3 font-mono text-xs">PACKET_ADD/REMOVE_FILTER</td>
                    <td className="py-2 px-3">0x904-0x905</td>
                    <td className="py-2 px-3 text-muted-foreground">Manage packet filters</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">DioProcessSDK C++ Class</h2>
        <p className="text-muted-foreground">
          Header-only SDK class with 60+ wrapper functions. Include <code>sdk/DioProcessSDK.h</code> and use directly.
        </p>

        <div className="p-4 rounded-lg border border-violet/30 bg-violet/5">
          <h3 className="font-semibold mb-3">Quick Start</h3>
          <pre className="text-xs bg-secondary/50 p-3 rounded overflow-x-auto">{`#include "DioProcessSDK.h"

DioProcessSDK sdk;
if (sdk.Open()) {
    // Protect current process
    sdk.ProtectProcess(GetCurrentProcessId());
    
    // Start hypervisor
    sdk.HvStart();
    
    // Enumerate callbacks
    BYTE buffer[4096];
    DWORD bytes;
    sdk.EnumProcessCallbacks(buffer, sizeof(buffer), &bytes);
    
    sdk.Close();
}`}</pre>
        </div>

        <div className="space-y-4 mt-6">
          <h3 className="text-lg font-semibold">SDK Methods by Category</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Connection</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>Open() → BOOL</li>
                <li>Close() → void</li>
                <li>IsOpen() → BOOL</li>
                <li>GetHandle() → HANDLE</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Collection</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>StartCollection() → BOOL</li>
                <li>StopCollection() → BOOL</li>
                <li>GetCollectionState(response*) → BOOL</li>
                <li>RegisterCallbacks() → BOOL</li>
                <li>UnregisterCallbacks() → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Process Protection</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>ProtectProcess(pid) → BOOL</li>
                <li>UnprotectProcess(pid) → BOOL</li>
                <li>ProtectProcessWithLevel(pid, level) → BOOL</li>
                <li>EnablePrivileges(pid) → BOOL</li>
                <li>ClearDebugFlags(pid) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Callback Enumeration</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>EnumProcessCallbacks(buf, size, bytes*) → BOOL</li>
                <li>EnumThreadCallbacks(buf, size, bytes*) → BOOL</li>
                <li>EnumImageCallbacks(buf, size, bytes*) → BOOL</li>
                <li>EnumObjectCallbacks(buf, size, bytes*) → BOOL</li>
                <li>EnumRegistryCallbacks(buf, size, bytes*) → BOOL</li>
                <li>EnumMinifilters(buf, size, bytes*) → BOOL</li>
                <li>EnumDrivers(buf, size, bytes*) → BOOL</li>
                <li>EnumPspCidTable(buf, size, bytes*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Callback Removal</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>RemoveProcessCallback(index) → BOOL</li>
                <li>RemoveThreadCallback(index) → BOOL</li>
                <li>RemoveImageCallback(index) → BOOL</li>
                <li>RemoveObjectCallback(index, type, pre, post) → BOOL</li>
                <li>RemoveRegistryCallback(index) → BOOL</li>
                <li>UnlinkMinifilter(name) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Callback Restore</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>RestoreProcessCallback(index) → BOOL</li>
                <li>RestoreThreadCallback(index) → BOOL</li>
                <li>RestoreImageCallback(index) → BOOL</li>
                <li>RestoreObjectCallback(index, type, pre, post) → BOOL</li>
                <li>RestoreRegistryCallback(index) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Kernel Injection</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>KernelInjectShellcode(pid, code, size, resp*) → BOOL</li>
                <li>KernelInjectDll(pid, path, resp*) → BOOL</li>
                <li>KernelManualMap(pid, bytes, size, flags, resp*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Hypervisor Control</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>HvStart() → BOOL</li>
                <li>HvStop() → BOOL</li>
                <li>HvPing(resp*) → BOOL</li>
                <li>HvInstallHooks() → BOOL</li>
                <li>HvRemoveHooks() → BOOL</li>
                <li>HvProtectProcess(pid) → BOOL</li>
                <li>HvUnprotectProcess(pid) → BOOL</li>
                <li>HvListProtected(resp*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">HV Driver Hiding</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>HvHideDriver(name) → BOOL</li>
                <li>HvUnhideDriver(name) → BOOL</li>
                <li>HvIsDriverHidden(name, resp*) → BOOL</li>
                <li>HvListHiddenDrivers(resp*) → BOOL</li>
                <li>HvClearHiddenDrivers() → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">HV Memory Operations</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>HvReadVm(pid, addr, size, buf, bytes*) → BOOL</li>
                <li>HvWriteVm(pid, addr, data, size, bytes*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Early Injection</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>EarlyInjectArm(proc, dll, method, oneShot) → BOOL</li>
                <li>EarlyInjectDisarm() → BOOL</li>
                <li>EarlyInjectStatus(resp*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Hiding Features</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>HideFile(path) / UnhideFile(path) → BOOL</li>
                <li>ListHiddenFiles(resp*) → BOOL</li>
                <li>HideProcess(pid) / UnhideProcess(pid) → BOOL</li>
                <li>ListHiddenProcesses(resp*) → BOOL</li>
                <li>HidePort(port) / UnhidePort(index) → BOOL</li>
                <li>ListHiddenPorts(resp*) → BOOL</li>
                <li>HideMemory(pid, addr, prot) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Physical Memory</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>TranslateVa(pid, va, resp*) → BOOL</li>
                <li>ReadPhysical(pa, buf, size, bytes*) → BOOL</li>
                <li>WritePhysical(pa, data, size, bytes*) → BOOL</li>
                <li>PhysReadVm(pid, va, buf, size, bytes*) → BOOL</li>
                <li>EnumVmRegions(pid, buf, size, bytes*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">EPT Hooks</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>EptHookInstall(pid, addr, patch, size, resp*) → BOOL</li>
                <li>EptHookRemove(index) → BOOL</li>
                <li>EptHookList(resp*) → BOOL</li>
                <li>RegChangeInstall(pid, addr, reg, val, resp*) → BOOL</li>
                <li>RegChangeRemove(index) → BOOL</li>
                <li>RegChangeList(resp*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Process Control</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>KillProcessTerminate(pid) → BOOL</li>
                <li>KillProcessUnmap(pid) → BOOL</li>
                <li>KillProcessPebCorrupt(pid) → BOOL</li>
                <li>SuspendProcess(pid) / ResumeProcess(pid) → BOOL</li>
                <li>SuspendThread(tid) / ResumeThread(tid) → BOOL</li>
                <li>TerminateThread(tid) → BOOL</li>
                <li>EnumSystemThreads(buf, size, bytes*) → BOOL</li>
                <li>EnumAllKernelThreads(buf, size, bytes*) → BOOL</li>
              </ul>
            </div>

            <div className="p-4 rounded-lg border border-border/50 bg-card/50">
              <h4 className="font-semibold mb-2 text-violet">Packet Capture</h4>
              <ul className="text-xs font-mono space-y-1 text-muted-foreground">
                <li>PacketStartCapture(pid) → BOOL</li>
                <li>PacketStopCapture() → BOOL</li>
                <li>PacketGetState(resp*) → BOOL</li>
                <li>PacketGetPackets(buf, size, bytes*) → BOOL</li>
                <li>PacketAddFilter(rule*) → BOOL</li>
                <li>PacketRemoveFilter(index) → BOOL</li>
                <li>PacketClearFilters() / PacketClearBuffer() → BOOL</li>
              </ul>
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
            <h3 className="font-semibold mb-2 font-mono text-violet">KernelInjectShellcodeResponse</h3>
            <p className="text-sm text-muted-foreground mb-2">Kernel shellcode injection result</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct KernelInjectShellcodeResponse {
    ULONG64 AllocatedAddress;
    BOOLEAN Success;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">HvPingResponse</h3>
            <p className="text-sm text-muted-foreground mb-2">Hypervisor status</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct HvPingResponse {
    BOOLEAN IsRunning;
    BOOLEAN HooksInstalled;
    ULONG ProtectedProcessCount;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">TranslateVaResponse</h3>
            <p className="text-sm text-muted-foreground mb-2">Page table walk result</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct TranslateVaResponse {
    ULONG64 Cr3;
    PageTableEntryResult Pml4e, Pdpte, Pde, Pte;
    ULONG64 PhysicalAddress;
    ULONG PageSize;
    UCHAR WalkDepth;
    UCHAR Success;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">EptHookInstallResponse</h3>
            <p className="text-sm text-muted-foreground mb-2">EPT hook installation result</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct EptHookInstallResponse {
    ULONG HookIndex;
    BOOLEAN Success;
};`}</pre>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 font-mono text-violet">CapturedPacketData</h3>
            <p className="text-sm text-muted-foreground mb-2">WFP captured packet</p>
            <pre className="text-xs text-muted-foreground bg-secondary/50 p-2 rounded">{`struct CapturedPacketData {
    ULONG64 Id, Timestamp;
    ULONG ProcessId;
    PacketDirection Direction;
    PacketProtocol Protocol;
    ULONG LocalAddr, RemoteAddr;
    USHORT LocalPort, RemotePort;
    USHORT PayloadSize;
    UCHAR Payload[1500];
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
