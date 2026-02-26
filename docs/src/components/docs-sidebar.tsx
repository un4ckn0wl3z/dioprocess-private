"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  BookOpen,
  Rocket,
  Monitor,
  Syringe,
  Terminal,
  Layers,
  Eye,
  HardDrive,
  Key,
  Cpu,
  Download,
  Shield,
  Zap as Lightning,
  Database,
  Bell,
  Zap,
  MemoryStick,
  EyeOff,
  FileCode,
  Power,
  Lock,
} from "lucide-react";

interface NavItem {
  title: string;
  href: string;
  icon?: React.ElementType;
  items?: NavItem[];
}

const navigation: NavItem[] = [
  {
    title: "Getting Started",
    href: "/docs/getting-started",
    icon: Rocket,
  },
  {
    title: "Usermode Features",
    href: "/docs/usermode",
    icon: Monitor,
    items: [
      { title: "Process Monitoring", href: "/docs/usermode/process-monitoring" },
      { title: "DLL Injection", href: "/docs/usermode/dll-injection", icon: Syringe },
      { title: "Shellcode Injection", href: "/docs/usermode/shellcode-injection", icon: Terminal },
      { title: "Process Creation", href: "/docs/usermode/process-creation", icon: Layers },
      { title: "Hook Detection", href: "/docs/usermode/hook-detection", icon: Eye },
      { title: "Memory Operations", href: "/docs/usermode/memory-operations", icon: HardDrive },
      { title: "Token Theft", href: "/docs/usermode/token-theft", icon: Key },
    ],
  },
  {
    title: "Kernel Driver",
    href: "/docs/kernel",
    icon: Cpu,
    items: [
      { title: "Installation", href: "/docs/kernel/installation", icon: Download },
      { title: "Process Protection", href: "/docs/kernel/process-protection", icon: Shield },
      { title: "Privilege Escalation", href: "/docs/kernel/privilege-escalation", icon: Lightning },
      { title: "Callback Enumeration", href: "/docs/kernel/callback-enumeration", icon: Database },
      { title: "Kernel Injection", href: "/docs/kernel/kernel-injection", icon: Syringe },
      { title: "Early Injection", href: "/docs/kernel/early-injection", icon: Rocket },
      { title: "System Events", href: "/docs/kernel/system-events", icon: Bell },
    ],
  },
  {
    title: "Hypervisor",
    href: "/docs/hypervisor",
    icon: Zap,
    items: [
      { title: "EPT Hooks", href: "/docs/hypervisor/ept-hooks", icon: FileCode },
      { title: "Memory Scanner", href: "/docs/hypervisor/memory-scanner", icon: MemoryStick },
      { title: "Ring -1 Injection", href: "/docs/hypervisor/ring-1-injection", icon: Syringe },
      { title: "Process Hiding", href: "/docs/hypervisor/process-hiding", icon: EyeOff },
    ],
  },
  {
    title: "UEFI Bootkit",
    href: "/docs/uefi",
    icon: Power,
    items: [
      { title: "DSE Bypass", href: "/docs/uefi/dse-bypass", icon: Shield },
      { title: "KPP Bypass", href: "/docs/uefi/kpp-bypass", icon: Lock },
    ],
  },
  {
    title: "API Reference",
    href: "/docs/api-reference",
    icon: BookOpen,
  },
];

function NavLink({ item, depth = 0 }: { item: NavItem; depth?: number }) {
  const pathname = usePathname();
  const isActive = pathname === item.href;
  const isParentActive = item.items?.some((child) => pathname === child.href);
  const Icon = item.icon;

  return (
    <div>
      <Link
        href={item.href}
        className={cn(
          "flex items-center gap-2 px-3 py-2 text-sm rounded-md transition-colors",
          depth > 0 && "ml-4 pl-4 border-l border-border/50",
          isActive
            ? "bg-violet/10 text-violet font-medium"
            : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
        )}
      >
        {Icon && depth === 0 && <Icon className="w-4 h-4" />}
        {item.title}
      </Link>
      {item.items && (isActive || isParentActive) && (
        <div className="mt-1 space-y-1">
          {item.items.map((child) => (
            <NavLink key={child.href} item={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export function DocsSidebar() {
  return (
    <aside className="hidden lg:block w-64 shrink-0">
      <div className="sticky top-20 h-[calc(100vh-5rem)]">
        <ScrollArea className="h-full py-6 pr-4">
          <nav className="space-y-2">
            {navigation.map((item) => (
              <NavLink key={item.href} item={item} />
            ))}
          </nav>
        </ScrollArea>
      </div>
    </aside>
  );
}

export function MobileDocsSidebar() {
  return (
    <nav className="space-y-2 p-4">
      {navigation.map((item) => (
        <NavLink key={item.href} item={item} />
      ))}
    </nav>
  );
}
