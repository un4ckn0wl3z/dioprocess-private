import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function ExamplesPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">SDK Examples</h1>
          <Badge variant="default" className="bg-cyan-600">C/C++</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Complete code examples demonstrating various DioProcess SDK features.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hello World</h2>
        <p className="text-muted-foreground">
          Basic example demonstrating connection and common operations:
        </p>
        <CodeBlock
          language="cpp"
          filename="hello_world.cpp"
          code={`#include <iostream>
#include <iomanip>
#include "DioProcessSDK.h"

void PrintHex(ULONG64 value) {
    std::cout << "0x" << std::hex << std::setfill('0') 
              << std::setw(16) << value << std::dec;
}

int main() {
    std::cout << "=== DioProcess SDK Hello World ===" << std::endl;

    DioProcessSDK sdk;

    // Connect to driver
    if (!sdk.Open()) {
        std::cerr << "Failed to open driver. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Connected to driver" << std::endl;

    // Check hypervisor status
    HvPingResponse hvStatus = {};
    if (sdk.HvPing(&hvStatus)) {
        std::cout << "[*] Hypervisor: " << (hvStatus.IsRunning ? "Running" : "Not running") << std::endl;
    }

    // Enumerate process callbacks
    BYTE buffer[8192];
    DWORD bytesReturned;
    if (sdk.EnumProcessCallbacks(buffer, sizeof(buffer), &bytesReturned)) {
        ULONG count = *(ULONG*)buffer;
        std::cout << "[*] Process callbacks: " << count << std::endl;
        
        CallbackInformation* callbacks = (CallbackInformation*)(buffer + sizeof(ULONG));
        for (ULONG i = 0; i < count && i < 5; i++) {
            std::cout << "    " << callbacks[i].ModuleName << " @ ";
            PrintHex(callbacks[i].CallbackAddress);
            std::cout << std::endl;
        }
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Process Protection</h2>
        <p className="text-muted-foreground">
          Protect a process from termination using PPL:
        </p>
        <CodeBlock
          language="cpp"
          filename="protect_process.cpp"
          code={`#include <iostream>
#include "DioProcessSDK.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: protect_process.exe <PID>" << std::endl;
        return 1;
    }

    ULONG pid = atoi(argv[1]);
    DioProcessSDK sdk;

    if (!sdk.Open()) {
        std::cerr << "Failed to connect to driver" << std::endl;
        return 1;
    }

    // Apply PPL protection
    if (sdk.ProtectProcess(pid)) {
        std::cout << "[+] Process " << pid << " is now protected" << std::endl;
        std::cout << "    Try to terminate it with Task Manager - it will fail!" << std::endl;
        
        std::cout << "Press Enter to remove protection..." << std::endl;
        std::cin.get();
        
        // Remove protection
        if (sdk.UnprotectProcess(pid)) {
            std::cout << "[+] Protection removed" << std::endl;
        }
    } else {
        std::cerr << "[-] Failed to protect process. Error: " << GetLastError() << std::endl;
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Callback Enumeration</h2>
        <p className="text-muted-foreground">
          Enumerate all registered kernel callbacks:
        </p>
        <CodeBlock
          language="cpp"
          filename="enum_callbacks.cpp"
          code={`#include <iostream>
#include <iomanip>
#include "DioProcessSDK.h"

void EnumCallbacks(DioProcessSDK& sdk, const char* name, 
    BOOL (DioProcessSDK::*enumFunc)(PVOID, DWORD, PDWORD)) {
    
    BYTE buffer[16384];
    DWORD bytesReturned;
    
    if ((sdk.*enumFunc)(buffer, sizeof(buffer), &bytesReturned)) {
        ULONG count = *(ULONG*)buffer;
        std::cout << name << ": " << count << " callback(s)" << std::endl;
        
        CallbackInformation* callbacks = (CallbackInformation*)(buffer + sizeof(ULONG));
        for (ULONG i = 0; i < count; i++) {
            std::cout << "  [" << std::setw(2) << i << "] ";
            std::cout << std::left << std::setw(40) << callbacks[i].ModuleName;
            std::cout << " @ 0x" << std::hex << callbacks[i].CallbackAddress;
            std::cout << std::dec << std::endl;
        }
        std::cout << std::endl;
    }
}

int main() {
    DioProcessSDK sdk;
    if (!sdk.Open()) return 1;

    std::cout << "=== Kernel Callback Enumeration ===" << std::endl << std::endl;

    EnumCallbacks(sdk, "Process Callbacks", &DioProcessSDK::EnumProcessCallbacks);
    EnumCallbacks(sdk, "Thread Callbacks", &DioProcessSDK::EnumThreadCallbacks);
    EnumCallbacks(sdk, "Image Callbacks", &DioProcessSDK::EnumImageCallbacks);

    // Object callbacks have different structure
    BYTE objBuffer[16384];
    DWORD bytesReturned;
    if (sdk.EnumObjectCallbacks(objBuffer, sizeof(objBuffer), &bytesReturned)) {
        ULONG count = *(ULONG*)objBuffer;
        std::cout << "Object Callbacks: " << count << std::endl;
        // Process ObjectCallbackInformation structures...
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Hypervisor Control</h2>
        <p className="text-muted-foreground">
          Start/stop the hypervisor and use Ring -1 features:
        </p>
        <CodeBlock
          language="cpp"
          filename="hypervisor_control.cpp"
          code={`#include <iostream>
#include "DioProcessSDK.h"

int main() {
    DioProcessSDK sdk;
    if (!sdk.Open()) return 1;

    // Check current status
    HvPingResponse status = {};
    sdk.HvPing(&status);
    std::cout << "Hypervisor running: " << (status.IsRunning ? "Yes" : "No") << std::endl;

    if (!status.IsRunning) {
        // Start hypervisor
        std::cout << "Starting hypervisor..." << std::endl;
        if (sdk.HvStart()) {
            std::cout << "[+] Hypervisor started!" << std::endl;
        } else {
            std::cerr << "[-] Failed to start hypervisor" << std::endl;
            sdk.Close();
            return 1;
        }
    }

    // Use Ring -1 features
    ULONG pid = GetCurrentProcessId();

    // Hide current process from Ring 0 enumeration
    if (sdk.HvProtectProcess(pid)) {
        std::cout << "[+] Process hidden via hypervisor" << std::endl;
    }

    std::cout << "Press Enter to unhide and stop hypervisor..." << std::endl;
    std::cin.get();

    // Unhide
    sdk.HvUnprotectProcess(pid);

    // Stop hypervisor
    if (sdk.HvStop()) {
        std::cout << "[+] Hypervisor stopped" << std::endl;
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Kernel Injection</h2>
        <p className="text-muted-foreground">
          Inject shellcode or DLL from kernel mode:
        </p>
        <CodeBlock
          language="cpp"
          filename="kernel_inject.cpp"
          code={`#include <iostream>
#include <fstream>
#include <vector>
#include "DioProcessSDK.h"

// Read shellcode from file
std::vector<BYTE> ReadFile(const char* path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    
    size_t size = file.tellg();
    file.seekg(0);
    
    std::vector<BYTE> buffer(size);
    file.read((char*)buffer.data(), size);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: kernel_inject.exe <PID> <shellcode.bin | path.dll>" << std::endl;
        return 1;
    }

    ULONG pid = atoi(argv[1]);
    const char* path = argv[2];
    
    DioProcessSDK sdk;
    if (!sdk.Open()) return 1;

    // Check if it's a DLL or shellcode
    std::string pathStr(path);
    bool isDll = pathStr.find(".dll") != std::string::npos;

    if (isDll) {
        // DLL injection
        KernelInjectDllRequest req = {};
        req.ProcessId = pid;
        wcscpy_s(req.DllPath, MAX_PATH, 
            std::wstring(pathStr.begin(), pathStr.end()).c_str());

        KernelInjectResponse resp = {};
        if (sdk.KernelInjectDll(&req, &resp)) {
            std::cout << "[+] DLL injected! Module base: 0x" 
                      << std::hex << resp.ModuleBase << std::endl;
        }
    } else {
        // Shellcode injection
        auto shellcode = ReadFile(path);
        if (shellcode.empty()) {
            std::cerr << "Failed to read shellcode" << std::endl;
            return 1;
        }

        KernelInjectShellcodeRequest req = {};
        req.ProcessId = pid;
        req.ShellcodeSize = (ULONG)shellcode.size();
        memcpy(req.Shellcode, shellcode.data(), 
               min(shellcode.size(), sizeof(req.Shellcode)));

        KernelInjectResponse resp = {};
        if (sdk.KernelInjectShellcode(&req, &resp)) {
            std::cout << "[+] Shellcode injected at: 0x" 
                      << std::hex << resp.ShellcodeAddress << std::endl;
        }
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">PspCidTable Enumeration</h2>
        <p className="text-muted-foreground">
          Enumerate all processes and threads via kernel CID table:
        </p>
        <CodeBlock
          language="cpp"
          filename="enum_pspcidtable.cpp"
          code={`#include <iostream>
#include <iomanip>
#include "DioProcessSDK.h"

int main() {
    DioProcessSDK sdk;
    if (!sdk.Open()) return 1;

    std::cout << "=== PspCidTable Enumeration ===" << std::endl;
    std::cout << "Comparing with ToolHelp32 to detect hidden processes" << std::endl << std::endl;

    BYTE buffer[131072];  // 128KB for large systems
    DWORD bytesReturned;
    
    if (sdk.EnumPspCidTable(buffer, sizeof(buffer), &bytesReturned)) {
        ULONG count = *(ULONG*)buffer;
        std::cout << "Total CID entries: " << count << std::endl << std::endl;
        
        CidTableEntry* entries = (CidTableEntry*)(buffer + sizeof(ULONG));
        
        // Count processes vs threads
        ULONG processes = 0, threads = 0;
        for (ULONG i = 0; i < count; i++) {
            if (entries[i].ObjectType == CidObjectTypeProcess) {
                processes++;
            } else {
                threads++;
            }
        }
        
        std::cout << "Processes: " << processes << std::endl;
        std::cout << "Threads: " << threads << std::endl << std::endl;
        
        // List processes
        std::cout << "Process List:" << std::endl;
        std::cout << std::left << std::setw(8) << "PID" 
                  << std::setw(30) << "Name"
                  << "EPROCESS" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        
        for (ULONG i = 0; i < count; i++) {
            if (entries[i].ObjectType == CidObjectTypeProcess) {
                std::cout << std::left << std::setw(8) << entries[i].Id
                          << std::setw(30) << entries[i].ProcessName
                          << "0x" << std::hex << entries[i].ObjectAddress 
                          << std::dec << std::endl;
            }
        }
    }

    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Building Examples</h2>
        <CodeBlock
          language="batch"
          code={`:: Using Visual Studio Developer Command Prompt
cl /EHsc /std:c++17 hello_world.cpp /Fe:hello_world.exe
cl /EHsc /std:c++17 protect_process.cpp /Fe:protect_process.exe
cl /EHsc /std:c++17 enum_callbacks.cpp /Fe:enum_callbacks.exe

:: Run (requires admin + driver loaded)
hello_world.exe`}
        />
      </section>
    </div>
  );
}
