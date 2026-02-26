import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import {
  FileCode,
  MemoryStick,
  Syringe,
  EyeOff,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "EPT Hooks",
    description: "Install execution-page hooks via hypervisor EPT",
    href: "/docs/hypervisor/ept-hooks",
    icon: FileCode,
  },
  {
    title: "Memory Scanner",
    description: "Physical memory scanning via CR3 page table walk",
    href: "/docs/hypervisor/memory-scanner",
    icon: MemoryStick,
  },
  {
    title: "Ring -1 Injection",
    description: "Shellcode and DLL injection via hypervisor physical memory access",
    href: "/docs/hypervisor/ring-1-injection",
    icon: Syringe,
  },
  {
    title: "Process Hiding",
    description: "Hide processes and drivers from Ring 0 enumeration",
    href: "/docs/hypervisor/process-hiding",
    icon: EyeOff,
  },
];

export default function HypervisorPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Hypervisor</h1>
          <Badge variant="destructive">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Intel VT-x based hypervisor bundled into DioProcess.sys for advanced security research 
          at the hypervisor level.
        </p>
      </div>

      <WarningBox variant="danger" title="Advanced Feature">
        The hypervisor operates below the kernel (Ring -1) and can bypass Ring 0 protections. 
        Use only on test systems with proper authorization.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Architecture</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm overflow-x-auto">
          <pre className="text-muted-foreground">{`┌─────────────────────────────────────────────────────────────┐
│                 DioProcess UI (Dioxus)                      │
│   Hypervisor Tab [Ring -1]                                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ DeviceIoControl
┌──────────────────────────▼──────────────────────────────────┐
│              callback crate (Rust bindings)                  │
│   hv_is_running(), hv_inject_shellcode(), hv_inject_dll()   │
└──────────────────────────┬──────────────────────────────────┘
                           │ IOCTL
┌──────────────────────────▼──────────────────────────────────┐
│                  DioProcess.sys                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  Ring 0: Kernel Driver (IOCTL handlers, memory ops) │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │ VMCALL                        │
│   ┌──────────────────────────▼──────────────────────────┐   │
│   │  Ring -1: Bundled Hypervisor (Intel VT-x, EPT)      │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘`}</pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Intel CPU</strong> with VT-x support</li>
          <li>• <strong>Hyper-V disabled</strong> — <code>bcdedit /set hypervisorlaunchtype off</code></li>
          <li>• <strong>DioProcess.sys loaded</strong> — Hypervisor is bundled, no separate driver</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid gap-4">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="hover:border-violet/30 transition-colors group">
                <CardHeader className="flex flex-row items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center group-hover:bg-red-500/20 transition-colors">
                    <feature.icon className="w-5 h-5 text-red-400" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
                    <CardDescription>{feature.description}</CardDescription>
                  </div>
                  <ArrowRight className="w-5 h-5 text-muted-foreground group-hover:text-red-400 transition-colors" />
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Key Capabilities</h2>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Physical Memory Access</h3>
            <p className="text-sm text-muted-foreground">
              Read/write physical memory via EPT translation, bypassing Ring 0 protections
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">EPT Hooks</h3>
            <p className="text-sm text-muted-foreground">
              Split-page hooks where read shows original bytes, execute shows patched bytes
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">VMCALL Interface</h3>
            <p className="text-sm text-muted-foreground">
              Hypercall interface for Ring 0 to Ring -1 communication
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">CR3 Page Table Walk</h3>
            <p className="text-sm text-muted-foreground">
              Physical memory scanning via direct page table traversal
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">PatchGuard Safety</h2>
        <p className="text-muted-foreground">
          Hypervisor operations <strong>do not trigger PatchGuard</strong>:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• ✓ Data-only modifications to usermode memory</li>
          <li>• ✓ Hypervisor operates outside PatchGuard&apos;s monitoring scope</li>
          <li>• ✓ No kernel code patching or table modifications</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Location</strong> — <code className="text-violet">kernelmode/.../Hypervisor/</code></li>
          <li>• <strong>Hypercall key</strong> — <code>69420</code> (hardcoded)</li>
          <li>• <strong>Virtualization</strong> — OS virtualized at driver load time</li>
        </ul>
      </section>
    </div>
  );
}
