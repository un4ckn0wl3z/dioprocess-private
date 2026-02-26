import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import {
  Eye,
  EyeOff,
  Network,
  FolderX,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "Process Hiding",
    description: "Hide processes from ring 0 enumeration via hypervisor EPT",
    href: "/docs/kernel-hiding/process-hiding",
    icon: EyeOff,
  },
  {
    title: "File Hiding",
    description: "Hide files and directories from filesystem queries",
    href: "/docs/kernel-hiding/file-hiding",
    icon: FolderX,
  },
  {
    title: "Port Hiding",
    description: "Hide TCP/UDP ports from network enumeration",
    href: "/docs/kernel-hiding/port-hiding",
    icon: Network,
  },
];

export default function KernelHidingPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Kernel Hiding</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Hide processes, files, and network ports from kernel-level enumeration using 
          hypervisor EPT manipulation.
        </p>
      </div>

      <WarningBox variant="danger" title="Security Research Only">
        These features are intended for authorized security research only. Hiding system 
        objects can interfere with security products and system stability.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The DioProcess hypervisor operates at Ring -1 (below the kernel), allowing it to 
          intercept and modify kernel data structures without being detected by the kernel 
          itself. This enables hiding of:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Processes</strong> — Unlink from ActiveProcessLinks and PspCidTable</li>
          <li>• <strong>Files</strong> — Filter directory enumeration results</li>
          <li>• <strong>Ports</strong> — Hide from netstat/Get-NetTCPConnection</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• DioProcess kernel driver with bundled hypervisor loaded</li>
          <li>• Intel VT-x capable processor with EPT support</li>
          <li>• Hyper-V disabled (hypervisorlaunchtype off)</li>
          <li>• Secure Boot disabled</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
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
        <h2 className="text-2xl font-bold">How EPT Hiding Works</h2>
        <p className="text-muted-foreground">
          Extended Page Tables (EPT) provide a second layer of address translation controlled 
          by the hypervisor. By manipulating EPT entries, the hypervisor can:
        </p>
        <ol className="space-y-2 text-muted-foreground list-decimal list-inside">
          <li>Intercept reads/writes to specific physical memory addresses</li>
          <li>Present different data to guest reads vs actual memory contents</li>
          <li>Modify kernel data structures transparently to the OS</li>
        </ol>
        <p className="text-muted-foreground mt-4">
          This makes hypervisor-level hiding extremely difficult to detect from within the 
          guest OS, as the kernel cannot directly observe the hypervisor&apos;s manipulations.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Considerations</h2>
        <p className="text-muted-foreground">
          While Ring -1 hiding is powerful, it can still be detected via:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Timing analysis (EPT violations add measurable latency)</li>
          <li>• CPUID leaf checks for virtualization</li>
          <li>• Comparison of multiple enumeration methods</li>
          <li>• Hardware performance counters</li>
          <li>• Another hypervisor observing the first hypervisor</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Hiding features are available in the Hypervisor tab and in the process context menu:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Hypervisor tab</strong> — Manage all hiding rules</li>
          <li>• <strong>Process context menu</strong> → Miscellaneous → <strong>Hide Process (Ring -1)</strong></li>
        </ul>
      </section>
    </div>
  );
}
