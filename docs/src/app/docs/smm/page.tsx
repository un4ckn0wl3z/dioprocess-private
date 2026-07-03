import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { WarningBox } from "@/components/warning-box";
import { Server, MemoryStick, Radio, Container, ArrowRight } from "lucide-react";

const features = [
  {
    title: "Architecture",
    description: "DXE + SMM driver split, communication buffer, SMI trigger flow",
    href: "/docs/smm/architecture",
    icon: Server,
  },
  {
    title: "Physical Memory",
    description: "Read/write physical memory from SMM via CR3 page table walk",
    href: "/docs/smm/physical-memory",
    icon: MemoryStick,
  },
  {
    title: "SMI Communication",
    description: "NVRAM-published communication buffer + software SMI trigger",
    href: "/docs/smm/smi-communication",
    icon: Radio,
  },
  {
    title: "QEMU Testing",
    description: "Pre-built OVMF firmware with embedded SMM/DXE drivers for safe testing",
    href: "/docs/smm/qemu-testing",
    icon: Container,
  },
];

export default function SmmPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">SMM</h1>
          <Badge variant="destructive" className="bg-purple-600/20 text-purple-400 border-purple-500/40">
            Ring -2
          </Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          System Management Mode is the deepest execution level on x86, running below even the
          hypervisor. The DioProcess SMM driver provides physical memory operations from this
          privileged environment, hidden inside SMRAM.
        </p>
      </div>

      <WarningBox variant="danger" title="Extreme Caution — Firmware Level">
        SMM code runs in hidden SMRAM outside OS visibility. Bugs here can corrupt hardware state,
        brick the machine, or leave the system in an unrecoverable state. Test only in QEMU/OVMF or
        on expendable hardware with a known-good SPI flash recovery path (e.g. CH341A programmer).
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why Ring -2?</h2>
        <p className="text-muted-foreground">
          SMM is isolated from every other execution level on the CPU. Code running in SMRAM cannot
          be inspected by the kernel, cannot be trapped by the hypervisor, and is not subject to
          PatchGuard. It is triggered only by a System Management Interrupt (SMI), which puts every
          CPU core into SMM in a well-defined state.
        </p>
        <div className="grid sm:grid-cols-2 gap-4 mt-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-purple-400">Isolation</h3>
            <p className="text-sm text-muted-foreground">
              Runs in SMRAM — a chipset-locked memory region invisible to Ring 0/-1
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-purple-400">No PatchGuard</h3>
            <p className="text-sm text-muted-foreground">
              KPP cannot monitor SMM code — it does not exist from the OS perspective
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-purple-400">Trigger via SMI</h3>
            <p className="text-sm text-muted-foreground">
              Software SMI (port 0xB2) forces every CPU into SMM to service the request
            </p>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-purple-400">Physical Memory Access</h3>
            <p className="text-sm text-muted-foreground">
              Direct physical memory read/write via CR3 page table walk
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Architecture Overview</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm overflow-x-auto">
          <pre className="text-muted-foreground">{`┌─────────────────────────────────────────────────────────┐
│  DioProcess UI (Dioxus) — SMM Tab [Ring -2]             │
└──────────────────────────┬──────────────────────────────┘
                           │ DeviceIoControl
┌──────────────────────────▼──────────────────────────────┐
│  Kernel Driver (DioProcess.sys)                          │
│  SMM/SmmCommunication.cpp — reads NVRAM, triggers SMI    │
└──────────────────────────┬──────────────────────────────┘
                           │ SMI (port 0xB2)
┌──────────────────────────▼──────────────────────────────┐
│  DioProcessDxe.efi (DXE Runtime Driver)                  │
│  - Allocates communication buffer at boot                │
│  - Publishes buffer address to NVRAM variable            │
│  - Bridges kernel driver ↔ SMM handler                   │
└──────────────────────────┬──────────────────────────────┘
                           │ MM_COMMUNICATE
┌──────────────────────────▼──────────────────────────────┐
│  DioProcessSmm.efi (SMM Driver)                          │
│  - Runs in SMRAM (hidden from OS)                        │
│  - Handles SMI requests                                  │
│  - Physical memory read/write via CR3 page table walk    │
└─────────────────────────────────────────────────────────┘`}</pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Why Both DXE and SMM Drivers?</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            • <strong className="text-foreground">SMM is isolated</strong> — runs in hidden SMRAM,
            only accessible via SMI interrupt
          </li>
          <li>
            • <strong className="text-foreground">No direct calls</strong> — the OS/kernel cannot
            call SMM functions directly
          </li>
          <li>
            • <strong className="text-foreground">DXE sets up the mailbox</strong> — allocates
            communication buffer during boot, publishes address to NVRAM
          </li>
          <li>
            • <strong className="text-foreground">Kernel reads NVRAM</strong> — gets buffer
            address, writes command, triggers SMI
          </li>
          <li>
            • <strong className="text-foreground">SMM reads buffer</strong> — executes command,
            writes result, returns from SMI
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Features</h2>
        <div className="grid gap-4">
          {features.map((feature) => (
            <Link key={feature.href} href={feature.href}>
              <Card className="hover:border-purple-500/40 transition-colors group">
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
        <h2 className="text-2xl font-bold">Requirements</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>
            • <strong>UEFI firmware with SMM support</strong> — both DXE and SMM drivers must be
            embedded in the platform firmware volume, or loaded from a modified OVMF build
          </li>
          <li>
            • <strong>DioProcess kernel driver loaded</strong> — required to trigger SMI from the OS
          </li>
          <li>
            • <strong>Administrator privileges</strong> — for kernel driver installation and NVRAM
            reads
          </li>
          <li>
            • <strong>QEMU + OVMF for development</strong> — do not test on production hardware
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Source Files</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm overflow-x-auto">
          <pre className="text-muted-foreground">{`efi/
├── DioProcessSmm/          # SMM driver (Ring -2) — EDK2 DXE_SMM_DRIVER
│   ├── SmmMain.c           # SMM entry point, SMI handler registration
│   ├── Smi.c               # SMI handler implementation
│   ├── Commands.c          # Command dispatcher (read/write physical memory)
│   ├── Memory.c            # Physical memory ops via CR3 page table walk
│   └── Nt.c                # NT kernel structure parsing (EPROCESS offsets)
├── DioProcessDxe/          # DXE runtime driver — kernel ↔ SMM bridge
│   ├── DxeMain.c           # DXE entry, MM_COMMUNICATION2 setup
│   └── Utils.c             # Virtual address translation helpers
├── build/                  # Pre-built .efi binaries
│   ├── DioProcessSmm.efi
│   └── DioProcessDxe.efi
└── ovmf/                   # QEMU testing files
    ├── OVMF_CODE.fd        # OVMF with embedded SMM/DXE drivers
    ├── OVMF_VARS.fd        # NVRAM variables
    └── run_qemu.bat        # QEMU launch script with SMM support

kernelmode/DioProcess/DioProcessDriver/
└── SMM/SmmCommunication.cpp   # Kernel-side SMI trigger + NVRAM reader

crates/smm/                    # Rust bindings
├── src/driver.rs              # SMM IOCTL wrappers
├── src/types.rs               # SmmCommand, SmmResponse, SmmStatus
└── src/error.rs               # SmmError enum`}</pre>
        </div>
      </section>
    </div>
  );
}
