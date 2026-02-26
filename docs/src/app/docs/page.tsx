import Link from "next/link";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Monitor,
  Cpu,
  Zap,
  Power,
  ArrowRight,
  Rocket,
} from "lucide-react";

const sections = [
  {
    title: "Getting Started",
    description: "Installation, requirements, and first run",
    href: "/docs/getting-started",
    icon: Rocket,
  },
  {
    title: "Usermode Features",
    description: "Process monitoring, DLL injection, shellcode injection, and more",
    href: "/docs/usermode",
    icon: Monitor,
    badge: "Ring 3",
  },
  {
    title: "Kernel Driver",
    description: "Process protection, privilege escalation, callback enumeration",
    href: "/docs/kernel",
    icon: Cpu,
    badge: "Ring 0",
  },
  {
    title: "Hypervisor",
    description: "EPT hooks, memory scanner, Ring -1 injection",
    href: "/docs/hypervisor",
    icon: Zap,
    badge: "Ring -1",
    badgeVariant: "destructive" as const,
  },
  {
    title: "UEFI Bootkit",
    description: "DSE bypass, PatchGuard bypass, boot-time patching",
    href: "/docs/uefi",
    icon: Power,
    badge: "EFI",
  },
];

export default function DocsPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Documentation</h1>
        <p className="text-lg text-muted-foreground">
          Welcome to the DioProcess documentation. <span className="italic">Dio</span> means <span className="italic">God</span> in Latin — 
          DioProcess is the <span className="text-violet font-medium">God Process</span> for Windows, 
          the ultimate process manager and security research toolkit.
        </p>
      </div>

      <div className="grid gap-4">
        {sections.map((section) => (
          <Link key={section.href} href={section.href}>
            <Card className="hover:border-violet/30 transition-colors group">
              <CardHeader className="flex flex-row items-center gap-4">
                <div className="w-12 h-12 rounded-lg bg-violet/10 flex items-center justify-center group-hover:bg-violet/20 transition-colors">
                  <section.icon className="w-6 h-6 text-violet" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <CardTitle className="text-xl">{section.title}</CardTitle>
                    {section.badge && (
                      <Badge variant={section.badgeVariant || "outline"} className="text-xs">
                        {section.badge}
                      </Badge>
                    )}
                  </div>
                  <CardDescription>{section.description}</CardDescription>
                </div>
                <ArrowRight className="w-5 h-5 text-muted-foreground group-hover:text-violet transition-colors" />
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>

      <div className="border-t border-border/40 pt-8">
        <h2 className="text-2xl font-bold mb-4">Quick Links</h2>
        <div className="grid sm:grid-cols-2 gap-4">
          <Link
            href="/docs/getting-started"
            className="p-4 rounded-lg border border-border/50 hover:border-violet/30 transition-colors"
          >
            <h3 className="font-semibold mb-1">Installation Guide</h3>
            <p className="text-sm text-muted-foreground">
              Get DioProcess up and running on your system
            </p>
          </Link>
          <Link
            href="/docs/kernel/installation"
            className="p-4 rounded-lg border border-border/50 hover:border-violet/30 transition-colors"
          >
            <h3 className="font-semibold mb-1">Driver Installation</h3>
            <p className="text-sm text-muted-foreground">
              Load the kernel driver for advanced features
            </p>
          </Link>
          <Link
            href="/docs/usermode/dll-injection"
            className="p-4 rounded-lg border border-border/50 hover:border-violet/30 transition-colors"
          >
            <h3 className="font-semibold mb-1">DLL Injection Methods</h3>
            <p className="text-sm text-muted-foreground">
              Learn about the 7 injection techniques
            </p>
          </Link>
          <Link
            href="/docs/api-reference"
            className="p-4 rounded-lg border border-border/50 hover:border-violet/30 transition-colors"
          >
            <h3 className="font-semibold mb-1">API Reference</h3>
            <p className="text-sm text-muted-foreground">
              IOCTLs, structures, and technical details
            </p>
          </Link>
        </div>
      </div>
    </div>
  );
}
