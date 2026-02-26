import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Monitor,
  Syringe,
  Terminal,
  Layers,
  Eye,
  HardDrive,
  Key,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "Process Monitoring",
    description: "Enumerate processes, threads, handles, modules, and memory regions",
    href: "/docs/usermode/process-monitoring",
    icon: Monitor,
  },
  {
    title: "DLL Injection",
    description: "7 injection methods from LoadLibrary to Manual Mapping",
    href: "/docs/usermode/dll-injection",
    icon: Syringe,
  },
  {
    title: "Shellcode Injection",
    description: "Classic, Web Staging, and Threadless injection techniques",
    href: "/docs/usermode/shellcode-injection",
    icon: Terminal,
  },
  {
    title: "Process Creation",
    description: "Hollowing, Ghosting, Herpaderping, and PPID Spoofing",
    href: "/docs/usermode/process-creation",
    icon: Layers,
  },
  {
    title: "Hook Detection",
    description: "IAT scanning and automatic DLL unhooking",
    href: "/docs/usermode/hook-detection",
    icon: Eye,
  },
  {
    title: "Memory Operations",
    description: "Commit, decommit, free memory regions with hex dump viewer",
    href: "/docs/usermode/memory-operations",
    icon: HardDrive,
  },
  {
    title: "Token Theft",
    description: "Steal and impersonate process tokens",
    href: "/docs/usermode/token-theft",
    icon: Key,
  },
];

export default function UsermodePage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Usermode Features</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Comprehensive process monitoring and manipulation using Windows APIs. 
          These features work without the kernel driver and provide powerful 
          capabilities for security research and analysis.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The usermode features are implemented in the following Rust crates:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            <code className="text-violet">process</code> — Process enumeration, threads, handles, modules, memory regions, string scanning
          </li>
          <li>
            <code className="text-violet">network</code> — TCP/UDP connection enumeration via IP Helper API
          </li>
          <li>
            <code className="text-violet">service</code> — Windows Service Control Manager operations
          </li>
          <li>
            <code className="text-violet">misc</code> — DLL injection, shellcode injection, process creation, token theft, unhooking
          </li>
        </ul>
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
        <h2 className="text-2xl font-bold">Key Capabilities</h2>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Process Tree View</h3>
            <p className="text-sm text-muted-foreground">
              Hierarchical view of parent-child process relationships with expand/collapse controls
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Real-time Graphs</h3>
            <p className="text-sm text-muted-foreground">
              Per-process CPU and memory usage graphs with 60-second rolling history
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">String Scanning</h3>
            <p className="text-sm text-muted-foreground">
              Extract ASCII and UTF-16 strings from process memory with export capability
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">CSV Export</h3>
            <p className="text-sm text-muted-foreground">
              Export process, network, and service data to CSV files
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
