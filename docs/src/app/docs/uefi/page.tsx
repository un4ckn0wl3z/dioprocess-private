import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import { Shield, Lock, ArrowRight } from "lucide-react";

const features = [
  {
    title: "DSE Bypass",
    description: "Disable Driver Signature Enforcement at boot time",
    href: "/docs/uefi/dse-bypass",
    icon: Shield,
  },
  {
    title: "KPP Bypass",
    description: "Disable PatchGuard (Kernel Patch Protection) at boot time",
    href: "/docs/uefi/kpp-bypass",
    icon: Lock,
  },
];

export default function UefiPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">UEFI Bootkit</h1>
          <Badge variant="secondary" className="bg-purple-500/20 text-purple-400">EFI</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Boot-time kernel patching via a UEFI DXE driver. Bypass DSE and PatchGuard 
          before Windows loads.
        </p>
      </div>

      <WarningBox variant="danger" title="Extreme Caution Required">
        The UEFI bootkit modifies the Windows boot process. Incorrect use can render 
        your system unbootable. Use only on test systems with proper backups.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Architecture</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm overflow-x-auto">
          <pre className="text-muted-foreground">{`┌──────────────────────────────────────────────────┐
│  DioProcess UI (Dioxus) — UEFI Tab               │
│  [DSE: ON/OFF] [PatchGuard: ON/OFF]              │
│  [Install to ESP] [Remove from ESP] [Status]     │
└──────────────────┬───────────────────────────────┘
                   │ Win32 API (SetFirmwareEnvironmentVariableW)
                   │ + std::process::Command (mountvol, bcdedit)
┌──────────────────▼───────────────────────────────┐
│  UEFI NVRAM Variables (persist across reboots)   │
│  {D10PR0C5-1337-4242-BEEF-CAFEBABE0001}         │
│  DioProcessDseBypass = 0 or 1                    │
│  DioProcessKppBypass = 0 or 1                    │
└──────────────────┬───────────────────────────────┘
                   │ Read at boot time
┌──────────────────▼───────────────────────────────┐
│  DioProcessEfi.efi (UEFI DXE Driver — EDK2/C)   │
│  1. Hook gBS->ExitBootServices                   │
│  2. Read NVRAM config variables                  │
│  3. If DseBypass=1: NOP g_CiOptions in winload   │
│  4. If KppBypass=1: RET PatchGuard init          │
│  5. Restore original and call ExitBootServices   │
└──────────────────────────────────────────────────┘`}</pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>UEFI system</strong> — Legacy BIOS not supported</li>
          <li>• <strong>Secure Boot disabled</strong> — Required for unsigned EFI driver</li>
          <li>• <strong>Administrator privileges</strong> — For ESP access and NVRAM writes</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid gap-4">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="hover:border-purple-500/30 transition-colors group">
                <CardHeader className="flex flex-row items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center group-hover:bg-purple-500/20 transition-colors">
                    <feature.icon className="w-5 h-5 text-purple-400" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
                    <CardDescription>{feature.description}</CardDescription>
                  </div>
                  <ArrowRight className="w-5 h-5 text-muted-foreground group-hover:text-purple-400 transition-colors" />
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Installation</h2>
        <p className="text-muted-foreground">
          EFI driver installation is handled from the <strong>title bar</strong> buttons:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Install EFI</strong> — Downloads from private GitHub repo and installs to ESP</li>
          <li>• <strong>Uninstall EFI</strong> — Removes boot entry and ESP files</li>
          <li>• With <code>-debug</code> flag: &quot;Browse Local File&quot; option available</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UEFI Tab</h2>
        <p className="text-muted-foreground">
          The UEFI Bootkit tab provides three sections:
        </p>
        <div className="grid sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Boot Patches</h3>
            <p className="text-sm text-muted-foreground">
              Toggle DSE/KPP bypass, save to NVRAM
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Boot Debug Log</h3>
            <p className="text-sm text-muted-foreground">
              Read/clear UEFI debug log from ESP
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">System Information</h3>
            <p className="text-sm text-muted-foreground">
              Firmware type, Secure Boot status, test signing
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Boot Animation</h2>
        <p className="text-muted-foreground">
          The EFI driver displays a custom animated boot screen during the 5-second delay 
          before chainloading Windows. Uses GOP (Graphics Output Protocol).
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Format: BGRA32 (matches GOP PixelBlueGreenRedReserved8BitPerColor)</li>
          <li>• Frames pre-converted at build time (no runtime GIF decoding)</li>
          <li>• Recommended: max 256x256 resolution, 10-15 fps</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Source Files</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm">
          <pre className="text-muted-foreground">{`efi/DioProcessEfi/
├── DioProcessEfi.c    # DXE entry + ExitBootServices hook
├── Config.c/h         # NVRAM variable reader
├── Graphics.c/h       # GOP-based boot animation
├── Animation.h        # Pre-converted BGRA32 frames
├── PatchDse.c/h       # DSE bypass implementation
├── PatchKpp.c/h       # PatchGuard bypass implementation
├── PatternScan.c/h    # Wildcard byte pattern scanner
├── PeUtils.c/h        # PE32+ parsing utilities
├── DioProcessEfi.inf  # EDK2 module definition
└── DioProcessEfi.dsc  # EDK2 platform description`}</pre>
        </div>
      </section>
    </div>
  );
}
