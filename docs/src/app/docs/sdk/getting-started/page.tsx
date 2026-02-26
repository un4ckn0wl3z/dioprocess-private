import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function GettingStartedPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Getting Started</h1>
          <Badge variant="default" className="bg-cyan-600">C/C++</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Quick start guide to integrate the DioProcess SDK into your C/C++ projects.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Prerequisites</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Windows 10 or 11</strong> (x64)</li>
          <li>• <strong>Visual Studio 2019+</strong> with C++ desktop development workload</li>
          <li>• <strong>DioProcess driver loaded</strong></li>
          <li>• <strong>Administrator privileges</strong> for your application</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Step 1: Copy the Header</h2>
        <p className="text-muted-foreground">
          The SDK is a single header file. Copy <code>DioProcessSDK.h</code> to your project:
        </p>
        <CodeBlock
          language="text"
          code={`YourProject/
├── src/
│   └── main.cpp
└── include/
    └── DioProcessSDK.h`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Step 2: Include the Header</h2>
        <CodeBlock
          language="cpp"
          code={`#include "DioProcessSDK.h"

int main() {
    // SDK is ready to use
    return 0;
}`}
        />
        <p className="text-muted-foreground">
          The header includes all necessary Windows headers automatically.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Step 3: Connect to Driver</h2>
        <CodeBlock
          language="cpp"
          code={`#include <iostream>
#include "DioProcessSDK.h"

int main() {
    DioProcessSDK sdk;
    
    // Open connection to driver
    if (!sdk.Open()) {
        std::cerr << "Failed to connect to driver" << std::endl;
        std::cerr << "Error code: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "Connected to DioProcess driver!" << std::endl;
    
    // Use SDK functions here...
    
    // Clean up
    sdk.Close();
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Step 4: Build Your Project</h2>
        <p className="text-muted-foreground">Using Visual Studio Developer Command Prompt:</p>
        <CodeBlock
          language="batch"
          code={`cl /EHsc /std:c++17 main.cpp /Fe:myapp.exe`}
        />
        <p className="text-muted-foreground">Or create a Visual Studio project with these settings:</p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Platform: <code>x64</code></li>
          <li>• C++ Language Standard: <code>ISO C++17</code></li>
          <li>• Add include directory with <code>DioProcessSDK.h</code></li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Step 5: Run as Administrator</h2>
        <WarningBox variant="warning" title="Administrator Required">
          The SDK communicates with a kernel driver, which requires administrator privileges. 
          Always run your application elevated.
        </WarningBox>
        <p className="text-muted-foreground">
          To make your application always request elevation, add a manifest:
        </p>
        <CodeBlock
          language="xml"
          filename="app.manifest"
          code={`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Basic Usage Pattern</h2>
        <CodeBlock
          language="cpp"
          code={`#include "DioProcessSDK.h"

int main() {
    DioProcessSDK sdk;
    
    // 1. Open connection
    if (!sdk.Open()) {
        // Handle error - driver not loaded or not admin
        return 1;
    }
    
    // 2. Use SDK functions
    ULONG pid = GetCurrentProcessId();
    
    // Protect current process
    if (sdk.ProtectProcess(pid)) {
        // Success
    }
    
    // Enable all privileges  
    if (sdk.EnableAllPrivileges(pid)) {
        // Success
    }
    
    // Enumerate callbacks
    BYTE buffer[8192];
    DWORD bytesReturned;
    if (sdk.EnumProcessCallbacks(buffer, sizeof(buffer), &bytesReturned)) {
        ULONG count = *(ULONG*)buffer;
        // Process results...
    }
    
    // 3. Close connection
    sdk.Close();
    
    return 0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Error Handling</h2>
        <p className="text-muted-foreground">
          All SDK functions return <code>bool</code> or <code>BOOL</code>. On failure, 
          use <code>GetLastError()</code> for details:
        </p>
        <CodeBlock
          language="cpp"
          code={`if (!sdk.ProtectProcess(pid)) {
    DWORD error = GetLastError();
    switch (error) {
        case ERROR_ACCESS_DENIED:
            // Not running as admin
            break;
        case ERROR_FILE_NOT_FOUND:
            // Driver not loaded
            break;
        default:
            // Other error
            break;
    }
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Common Issues</h2>
        <div className="space-y-3 text-muted-foreground">
          <p><strong>Open() returns false:</strong></p>
          <ul className="pl-4 space-y-1">
            <li>• Not running as Administrator</li>
            <li>• DioProcess driver not loaded (<code>sc query DioProcess</code>)</li>
            <li>• Driver file blocked by security software</li>
          </ul>
          
          <p className="mt-4"><strong>Functions fail after Open() succeeds:</strong></p>
          <ul className="pl-4 space-y-1">
            <li>• Invalid parameters (check buffer sizes)</li>
            <li>• Target process doesn&apos;t exist</li>
            <li>• Hypervisor functions require HV to be started first</li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Next Steps</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• See <a href="/docs/sdk/examples" className="text-violet hover:underline">Examples</a> for complete code samples</li>
          <li>• Check <a href="/docs/sdk/api-reference" className="text-violet hover:underline">API Reference</a> for all available functions</li>
        </ul>
      </section>
    </div>
  );
}
