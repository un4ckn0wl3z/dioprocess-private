import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import {
  Download,
  Shield,
  Zap,
  Database,
  Syringe,
  Rocket,
  Bell,
  ArrowRight,
  Network,
} from "lucide-react";

const features = [
  {
    title: "Installation",
    description: "Load and configure the kernel driver",
    href: "/docs/kernel/installation",
    icon: Download,
  },
  {
    title: "Process Protection",
    description: "Apply/remove PPL protection via EPROCESS manipulation",
    href: "/docs/kernel/process-protection",
    icon: Shield,
  },
  {
    title: "Privilege Escalation",
    description: "Enable all 40 Windows privileges via TOKEN modification",
    href: "/docs/kernel/privilege-escalation",
    icon: Zap,
  },
  {
    title: "Callback Enumeration",
    description: "List process, thread, image, object, and registry callbacks",
    href: "/docs/kernel/callback-enumeration",
    icon: Database,
  },
  {
    title: "Kernel Injection",
    description: "Shellcode and DLL injection via RtlCreateUserThread",
    href: "/docs/kernel/kernel-injection",
    icon: Syringe,
  },
  {
    title: "Early Injection",
    description: "Inject DLLs before any user code executes",
    href: "/docs/kernel/early-injection",
    icon: Rocket,
  },
  {
    title: "Packet Capture",
    description: "WFP-based network packet capture and injection",
    href: "/docs/kernel/packet-capture",
    icon: Network,
  },
  {
    title: "System Events",
    description: "Real-time kernel event capture with SQLite persistence",
    href: "/docs/kernel/system-events",
    icon: Bell,
  },
];

export default function KernelPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Kernel Driver</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Direct kernel structure manipulation via a custom WDM driver. Provides 
          security research capabilities that bypass usermode restrictions.
        </p>
      </div>

      <WarningBox variant="danger" title="Security Research Only">
        The kernel driver provides powerful capabilities that can bypass Windows security 
        mechanisms. Use only on test systems with proper authorization.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The kernel driver is located in <code className="text-violet">kernelmode/DioProcess/</code> and provides:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Direct <code>_EPROCESS</code> and <code>_TOKEN</code> structure manipulation</li>
          <li>• Kernel callback enumeration and removal</li>
          <li>• PspCidTable enumeration for hidden process detection</li>
          <li>• Minifilter enumeration and unlinking</li>
          <li>• Kernel-mode injection via <code>RtlCreateUserThread</code></li>
          <li>• Real-time system event capture (17 event types)</li>
          <li>• Bundled Intel VT-x hypervisor for Ring -1 operations</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Windows Version Support</h2>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <h3 className="font-semibold text-green-400 mb-2">✓ Supported</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Windows 10: 1507 (10240) through 22H2 (19045)</li>
              <li>• Windows 11: 21H2 (22000) through 24H2 (26100)</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-red-500/30 bg-red-500/10">
            <h3 className="font-semibold text-red-400 mb-2">✗ Not Supported</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Windows 8.1 and earlier</li>
              <li>• 32-bit Windows</li>
              <li>• Windows Server (untested)</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid gap-4">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="hover:border-violet/30 transition-colors group">
                <CardHeader className="flex flex-row items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-violet/10 flex items-center justify-center group-hover:bg-violet/20 transition-colors">
                    <feature.icon className="w-5 h-5 text-violet" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
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
        <h2 className="text-2xl font-bold">PatchGuard Safety</h2>
        <p className="text-muted-foreground">
          The driver operations <strong>do not trigger PatchGuard/KPP</strong> because:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• ✓ Data-only modifications to per-process/per-token structures</li>
          <li>• ✓ No kernel code patching</li>
          <li>• ✓ No SSDT/IDT/GDT modifications</li>
          <li>• ✓ No function hooking</li>
        </ul>
        <p className="text-sm text-muted-foreground mt-2">
          PatchGuard only monitors code patches and critical kernel table modifications. 
          Direct writes to <code>_EPROCESS</code> and <code>_TOKEN</code> fields are pure data modifications.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Driver Architecture</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm">
          <pre className="text-muted-foreground">{`kernelmode/DioProcess/
├── DioProcess.sln              # Visual Studio solution
├── DioProcessDriver/
│   ├── DioProcessDriver.cpp    # Main driver code
│   ├── DioProcessDriver.h      # Protection structures, version detection
│   ├── DioProcessCommon.h      # Shared event structures + IOCTLs
│   ├── IRP/DeviceControl.cpp   # IOCTL handlers
│   ├── Callbacks/              # Kernel callback registration
│   ├── Enumeration/            # Callback/CidTable enumeration
│   ├── Injection/              # Kernel injection + early injection
│   └── Hypervisor/             # Bundled Intel VT-x hypervisor
└── DioProcessCli/              # Test CLI client`}</pre>
        </div>
      </section>
    </div>
  );
}
