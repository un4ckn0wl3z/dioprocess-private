import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FeatureCard } from "@/components/feature-card";
import { WarningBox } from "@/components/warning-box";
import {
  Monitor,
  Cpu,
  Zap,
  Shield,
  Github,
  ArrowRight,
  Terminal,
  Syringe,
  Eye,
  Lock,
  Database,
  Layers,
} from "lucide-react";

export default function Home() {
  return (
    <div className="flex flex-col">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-violet/5 via-transparent to-transparent" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-violet/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl" />
        
        <div className="container mx-auto px-4 py-24 md:py-32 relative">
          <div className="max-w-4xl mx-auto text-center">
            <Badge variant="outline" className="mb-6 border-violet/30 text-violet">
              v3.1.0 — Security Research Tool
            </Badge>
            
            <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
              Advanced Windows{" "}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-violet to-purple-400">
                Process Monitor
              </span>
            </h1>
            
            <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8">
              Modern desktop application for real-time system monitoring and low-level process manipulation. 
              Built with <span className="text-violet font-medium">Rust</span> and{" "}
              <span className="text-violet font-medium">Dioxus</span> for maximum performance.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
              <Button size="lg" className="bg-violet hover:bg-violet/90 gap-2" asChild>
                <Link href="/docs/getting-started">
                  Get Started
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </Button>
              <Button size="lg" variant="outline" className="gap-2 border-border/50" asChild>
                <a href="https://github.com/un4ckn0wl3z/dioprocess-private" target="_blank" rel="noopener noreferrer">
                  <Github className="w-4 h-4" />
                  View on GitHub
                </a>
              </Button>
              <Button size="lg" variant="outline" className="gap-2 border-border/50 border-indigo-500/30 hover:bg-indigo-500/10" asChild>
                <a href="https://discord.gg/ugYeeJRf5S" target="_blank" rel="noopener noreferrer">
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                  </svg>
                  Join Discord
                </a>
              </Button>
            </div>

            {/* Tech Stack Badges */}
            <div className="flex flex-wrap justify-center gap-3">
              {[
                { label: "Rust 2021", color: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
                { label: "Dioxus 0.6", color: "bg-purple-500/10 text-purple-400 border-purple-500/30" },
                { label: "Windows 10/11", color: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
                { label: "Intel VT-x", color: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" },
                { label: "WDM Driver", color: "bg-green-500/10 text-green-400 border-green-500/30" },
              ].map((tech) => (
                <Badge key={tech.label} variant="outline" className={tech.color}>
                  {tech.label}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Feature Cards Section */}
      <section className="py-20 border-t border-border/40">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Four Layers of{" "}
              <span className="text-violet">Power</span>
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              From usermode APIs to hypervisor-level control, DioProcess provides comprehensive 
              system access for security research and analysis.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6 max-w-5xl mx-auto">
            <FeatureCard
              title="Usermode Features"
              description="Comprehensive process monitoring and manipulation using Windows APIs"
              icon={Monitor}
              badge="Ring 3"
              features={[
                "Process, thread, handle, module enumeration",
                "7 DLL injection methods (LoadLibrary to Manual Map)",
                "3 shellcode injection techniques",
                "Process hollowing, ghosting, herpaderping",
                "Hook detection and DLL unhooking",
                "Token theft and impersonation",
              ]}
            />

            <FeatureCard
              title="Kernel Driver"
              description="Direct kernel structure manipulation via custom WDM driver"
              icon={Cpu}
              badge="Ring 0"
              features={[
                "Process protection (PPL) manipulation",
                "Token privilege escalation (40 privileges)",
                "Callback enumeration and removal",
                "PspCidTable enumeration (hidden process detection)",
                "Minifilter enumeration and unlinking",
                "Real-time system event capture (17 event types)",
              ]}
            />

            <FeatureCard
              title="Hypervisor"
              description="Intel VT-x based hypervisor for Ring -1 operations"
              icon={Zap}
              badge="Ring -1"
              badgeVariant="destructive"
              features={[
                "EPT hooks (Hex, Assembly, Detour modes)",
                "Physical memory scanner via CR3 page table walk",
                "Ring -1 shellcode and DLL injection",
                "Process hiding from Ring 0 enumeration",
                "Driver hiding via EPT manipulation",
                ".dph hook script system for portable hooks",
              ]}
            />

            <FeatureCard
              title="UEFI Bootkit"
              description="Boot-time kernel patching via UEFI DXE driver"
              icon={Shield}
              badge="EFI"
              badgeVariant="secondary"
              features={[
                "Driver Signature Enforcement (DSE) bypass",
                "PatchGuard (KPP) bypass",
                "Custom boot animation support",
                "NVRAM-based configuration persistence",
                "ExitBootServices hook architecture",
                "EDK2-based DXE driver",
              ]}
            />
          </div>
        </div>
      </section>

      {/* Capabilities Section */}
      <section className="py-20 bg-secondary/20 border-y border-border/40">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Comprehensive{" "}
              <span className="text-violet">Capabilities</span>
            </h2>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
            {[
              {
                icon: Syringe,
                title: "DLL Injection",
                desc: "7 methods: LoadLibrary, Thread Hijack, APC Queue, EarlyBird, Remote Mapping, Function Stomping, Manual Map",
              },
              {
                icon: Terminal,
                title: "Shellcode Injection",
                desc: "Classic, Web Staging (download from URL), and Threadless (hook-based, no new threads)",
              },
              {
                icon: Layers,
                title: "Process Masquerading",
                desc: "Hollowing, Ghosting, Ghostly Hollowing, Herpaderping, Herpaderping Hollowing",
              },
              {
                icon: Eye,
                title: "Hook Detection",
                desc: "IAT scanning for E9/E8/EB/FF25/MOV+JMP patterns with automatic unhooking",
              },
              {
                icon: Lock,
                title: "Security Research",
                desc: "PPL manipulation, privilege escalation, debug flag clearing, callback removal",
              },
              {
                icon: Database,
                title: "System Events",
                desc: "Real-time capture of 17 kernel event types with SQLite persistence",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="p-6 rounded-lg bg-card/50 border border-border/50 hover:border-violet/30 transition-colors"
              >
                <item.icon className="w-8 h-8 text-violet mb-4" />
                <h3 className="font-semibold mb-2">{item.title}</h3>
                <p className="text-sm text-muted-foreground">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Warning Section */}
      <section className="py-20">
        <div className="container mx-auto px-4 max-w-3xl">
          <WarningBox variant="danger" title="Security Research Tool">
            <p className="mb-3">
              DioProcess is designed for <strong>authorized security research and testing only</strong>. 
              The capabilities provided can bypass Windows security mechanisms and should only be used on 
              systems you own or have explicit permission to test.
            </p>
            <ul className="list-disc list-inside space-y-1">
              <li>Requires administrator privileges</li>
              <li>Kernel driver requires test signing mode or valid signature</li>
              <li>Hypervisor features require Hyper-V to be disabled</li>
              <li>UEFI bootkit requires Secure Boot to be disabled</li>
            </ul>
          </WarningBox>

          <div className="mt-8 text-center">
            <p className="text-muted-foreground mb-4">
              Ready to explore? Check out the documentation to get started.
            </p>
            <Button size="lg" className="bg-violet hover:bg-violet/90 gap-2" asChild>
              <Link href="/docs">
                Read the Docs
                <ArrowRight className="w-4 h-4" />
              </Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
