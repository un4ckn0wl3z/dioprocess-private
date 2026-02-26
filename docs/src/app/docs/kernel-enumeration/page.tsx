import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import {
  Database,
  Filter,
  HardDrive,
  FileCode,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "PspCidTable",
    description: "Enumerate all processes and threads via kernel CID handle table",
    href: "/docs/kernel-enumeration/pspcidtable",
    icon: Database,
  },
  {
    title: "Minifilters",
    description: "Enumerate and unlink filesystem minifilter drivers",
    href: "/docs/kernel-enumeration/minifilters",
    icon: Filter,
  },
  {
    title: "Driver Enumeration",
    description: "List all loaded kernel drivers with addresses and paths",
    href: "/docs/kernel-enumeration/drivers",
    icon: HardDrive,
  },
  {
    title: "Registry Callbacks",
    description: "Enumerate CmRegisterCallbackEx registry notification callbacks",
    href: "/docs/kernel-enumeration/registry-callbacks",
    icon: FileCode,
  },
];

export default function KernelEnumerationPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Kernel Enumeration</h1>
          <Badge variant="outline">Ring 0</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Enumerate kernel data structures, callbacks, and drivers that are not accessible 
          from usermode.
        </p>
      </div>

      <WarningBox variant="warning" title="Requires Kernel Driver">
        All kernel enumeration features require the DioProcess kernel driver to be loaded.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The Kernel Enumeration features provide visibility into kernel structures that are 
          normally hidden from usermode applications. This is useful for:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Detecting rootkits that hide processes via DKOM</li>
          <li>• Identifying EDR/AV minifilter drivers</li>
          <li>• Understanding which drivers are monitoring system activity</li>
          <li>• Security research and forensic analysis</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via the <strong>Kernel Utilities</strong> tab in the main navigation. Each 
          enumeration type has its own sub-tab with filtering, sorting, and export capabilities.
        </p>
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
        <h2 className="text-2xl font-bold">PatchGuard Safety</h2>
        <p className="text-muted-foreground">
          All enumeration operations are <strong>read-only</strong> and do not modify kernel 
          structures. They do not trigger PatchGuard/KPP because:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• No code patching occurs</li>
          <li>• No SSDT/IDT/GDT modifications</li>
          <li>• Only data structure traversal via documented/semi-documented methods</li>
        </ul>
      </section>
    </div>
  );
}
