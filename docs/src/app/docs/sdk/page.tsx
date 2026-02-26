import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Rocket,
  Code2,
  FileText,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "Getting Started",
    description: "Quick start guide to integrate the SDK into your C/C++ projects",
    href: "/docs/sdk/getting-started",
    icon: Rocket,
  },
  {
    title: "Examples",
    description: "Complete code examples demonstrating SDK features",
    href: "/docs/sdk/examples",
    icon: Code2,
  },
  {
    title: "API Reference",
    description: "Full documentation of all SDK classes, methods, and structures",
    href: "/docs/sdk/api-reference",
    icon: FileText,
  },
];

export default function SdkPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">DioProcess SDK</h1>
          <Badge variant="default" className="bg-cyan-600">C/C++</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Single-header C/C++ SDK for communicating with the DioProcess kernel driver. 
          Build custom tools that leverage Ring 0 and Ring -1 capabilities.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The DioProcessSDK is a header-only library that provides a clean interface for 
          communicating with the DioProcess kernel driver. It wraps all IOCTL codes, structures, 
          and provides inline wrapper functions with proper error handling.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Documentation</h2>
        <div className="grid gap-4">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="hover:border-violet/30 transition-colors group">
                <CardHeader className="flex flex-row items-center gap-4">
                  <div className="p-2 rounded-lg bg-violet/10">
                    <feature.icon className="w-6 h-6 text-violet" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg group-hover:text-violet transition-colors">
                      {feature.title}
                    </CardTitle>
                    <CardDescription>{feature.description}</CardDescription>
                  </div>
                  <ArrowRight className="w-5 h-5 text-muted-foreground group-hover:text-violet transition-colors" />
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Quick Example</h2>
        <pre className="p-4 rounded-lg bg-zinc-900 font-mono text-sm text-muted-foreground overflow-x-auto">
{`#include "DioProcessSDK.h"

int main() {
    DioProcessSDK sdk;
    
    if (!sdk.Open()) {
        return 1;  // Driver not loaded or not admin
    }
    
    // Protect current process (PPL)
    sdk.ProtectProcess(GetCurrentProcessId());
    
    // Enable all privileges
    sdk.EnableAllPrivileges(GetCurrentProcessId());
    
    // Enumerate kernel callbacks
    BYTE buffer[8192];
    DWORD bytesReturned;
    if (sdk.EnumProcessCallbacks(buffer, sizeof(buffer), &bytesReturned)) {
        ULONG count = *(ULONG*)buffer;
        // Process callback information...
    }
    
    sdk.Close();
    return 0;
}`}
        </pre>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">🛡️ Process Protection</h4>
            <p className="text-muted-foreground">Apply/remove PPL protection, enable all privileges</p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">🔍 Callback Enumeration</h4>
            <p className="text-muted-foreground">Process, thread, image, object, registry callbacks</p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">💉 Kernel Injection</h4>
            <p className="text-muted-foreground">Ring 0 shellcode and DLL injection</p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">🔮 Hypervisor Control</h4>
            <p className="text-muted-foreground">Start/stop HV, process hiding, EPT hooks</p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">📂 Driver Enumeration</h4>
            <p className="text-muted-foreground">List loaded drivers, minifilters, PspCidTable</p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h4 className="font-semibold mb-2">🕵️ Hiding Features</h4>
            <p className="text-muted-foreground">Process, file, port, driver hiding via Ring -1</p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Windows 10/11</strong> — x64 only</li>
          <li>• <strong>Visual Studio 2019+</strong> or compatible C++17 compiler</li>
          <li>• <strong>Administrator privileges</strong> — Required for driver communication</li>
          <li>• <strong>DioProcess driver loaded</strong> — The kernel driver must be running</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">File Structure</h2>
        <pre className="p-4 rounded-lg bg-zinc-900 font-mono text-sm text-muted-foreground">
{`sdk/
├── DioProcessSDK.h      # Single-header SDK (include this)
└── examples/
    └── hello_world.cpp  # Complete example program`}
        </pre>
      </section>
    </div>
  );
}
