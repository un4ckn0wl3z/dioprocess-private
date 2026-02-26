import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  FileUp,
  Ghost,
  Layers,
  ArrowRight,
} from "lucide-react";

const features = [
  {
    title: "File Bloating",
    description: "Inflate file size to bypass AV scanner size limits",
    href: "/docs/utilities/file-bloating",
    icon: FileUp,
  },
  {
    title: "Ghostly Hollowing",
    description: "Combine process ghosting with hollowing for fileless execution",
    href: "/docs/utilities/ghostly-hollowing",
    icon: Ghost,
  },
  {
    title: "Herpaderping",
    description: "Process herpaderping and herpaderping hollowing techniques",
    href: "/docs/utilities/herpaderping",
    icon: Layers,
  },
];

export default function UtilitiesPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Utilities</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Standalone utility tools for security research including file manipulation 
          and advanced process creation techniques.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The Utilities tab hosts standalone tools that don&apos;t fit into other categories. 
          These include file manipulation for AV evasion and combined process creation 
          techniques that merge multiple methods for enhanced stealth.
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
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access the Utilities tab from the main navigation bar, between Services and 
          System Events tabs. Each utility has its own section with dedicated controls 
          and status feedback.
        </p>
      </section>
    </div>
  );
}
