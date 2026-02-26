import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function ApiReferencePage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">API Reference</h1>
          <Badge variant="default" className="bg-cyan-600">C/C++</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Complete documentation of all DioProcess SDK classes, methods, and structures.
        </p>
      </div>

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
    
    // ... methods listed below
};`}
        />
      </section>

      <section className="space-y-4">
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
                <td className="py-2 px-3 font-mono text-xs">Open()</td>
                <td className="py-2 px-3 text-muted-foreground">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Opens connection to driver</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">Close()</td>
                <td className="py-2 px-3 text-muted-foreground">void</td>
                <td className="py-2 px-3 text-muted-foreground">Closes connection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">IsOpen()</td>
                <td className="py-2 px-3 text-muted-foreground">BOOL</td>
                <td className="py-2 px-3 text-muted-foreground">Check if connected</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Process Protection Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ProtectProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Apply PPL protection to process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UnprotectProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Remove PPL protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">EnableAllPrivileges(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Enable all token privileges</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">ClearDebugFlags(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Clear anti-debugging flags</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Enumeration Methods</h2>
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

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Removal Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">RemoveProcessCallback(ULONG index)</td>
                <td className="py-2 px-3 text-muted-foreground">Remove process callback by index</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">RemoveThreadCallback(ULONG index)</td>
                <td className="py-2 px-3 text-muted-foreground">Remove thread callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">RemoveImageCallback(ULONG index)</td>
                <td className="py-2 px-3 text-muted-foreground">Remove image load callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">RemoveObjectCallback(ULONG index)</td>
                <td className="py-2 px-3 text-muted-foreground">Remove object callback</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UnlinkMinifilter(LPCWSTR name)</td>
                <td className="py-2 px-3 text-muted-foreground">Unlink minifilter by name</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hypervisor Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvStart()</td>
                <td className="py-2 px-3 text-muted-foreground">Start the hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvStop()</td>
                <td className="py-2 px-3 text-muted-foreground">Stop the hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvPing(HvPingResponse*)</td>
                <td className="py-2 px-3 text-muted-foreground">Get hypervisor status</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvProtectProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Hide process via hypervisor</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvUnprotectProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvHideDriver(LPCWSTR name)</td>
                <td className="py-2 px-3 text-muted-foreground">Hide driver from enumeration</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvUnhideDriver(LPCWSTR name)</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide driver</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvInjectShellcode(pid, buf, size)</td>
                <td className="py-2 px-3 text-muted-foreground">Ring -1 shellcode injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HvInjectDll(pid, path)</td>
                <td className="py-2 px-3 text-muted-foreground">Ring -1 DLL injection</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hiding Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HideProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Hide process from Ring 0</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UnhideProcess(ULONG pid)</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide process</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HideFile(LPCWSTR path)</td>
                <td className="py-2 px-3 text-muted-foreground">Hide file from directory listing</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UnhideFile(LPCWSTR path)</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide file</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HidePort(USHORT port, UCHAR proto)</td>
                <td className="py-2 px-3 text-muted-foreground">Hide TCP/UDP port</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">UnhidePort(USHORT port, UCHAR proto)</td>
                <td className="py-2 px-3 text-muted-foreground">Unhide port</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel Injection Methods</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Method</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">KernelInjectShellcode(req*, resp*)</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 shellcode injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">KernelInjectDll(req*, resp*)</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 DLL injection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">KernelManualMap(req*, resp*)</td>
                <td className="py-2 px-3 text-muted-foreground">Ring 0 manual mapping</td>
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

// Kernel driver info
struct KernelDriverInfo {
    ULONG64 BaseAddress;
    ULONG Size;
    CHAR DriverName[MAX_DRIVER_NAME_LENGTH];
    WCHAR DriverPath[MAX_DRIVER_PATH_LENGTH];
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
};`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTL Codes</h2>
        <p className="text-muted-foreground">
          Direct IOCTL codes for advanced usage:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Code</th>
                <th className="text-left py-2 px-3 font-semibold">Name</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x805</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_PROTECT_PROCESS</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x806</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_UNPROTECT_PROCESS</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x807</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_ENABLE_PRIVILEGES</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x809</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_ENUM_PROCESS_CALLBACKS</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x820</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_HV_START</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x840</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_HV_INJECT_SHELLCODE</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">0x8B0</td>
                <td className="py-2 px-3 font-mono text-xs text-muted-foreground">IOCTL_DIOPROCESS_EPT_HOOK_INSTALL</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          See <code>DioProcessSDK.h</code> for complete IOCTL code list.
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
