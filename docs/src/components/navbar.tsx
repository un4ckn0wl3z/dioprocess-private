"use client";

import Link from "next/link";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import {
  Menu,
  Github,
  BookOpen,
  Cpu,
  Shield,
  Zap,
  Monitor,
} from "lucide-react";

const navItems = [
  { href: "/docs", label: "Documentation", icon: BookOpen },
  { href: "/docs/usermode", label: "Usermode", icon: Monitor },
  { href: "/docs/kernel", label: "Kernel", icon: Cpu },
  { href: "/docs/hypervisor", label: "Hypervisor", icon: Zap },
  { href: "/docs/uefi", label: "UEFI", icon: Shield },
];

export function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/80 backdrop-blur-xl">
      <div className="container mx-auto flex h-16 items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative">
            <div className="absolute inset-0 bg-violet/20 blur-xl rounded-full group-hover:bg-violet/30 transition-colors" />
            <div className="relative w-9 h-9 rounded-lg bg-gradient-to-br from-violet to-purple-700 flex items-center justify-center">
              <span className="text-white font-bold text-lg">D</span>
            </div>
          </div>
          <span className="font-bold text-xl tracking-tight">
            Dio<span className="text-violet">Process</span>
          </span>
        </Link>

        <nav className="hidden md:flex items-center gap-1">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-secondary/50 rounded-md transition-colors"
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="hidden sm:flex gap-2 border-border/50 hover:border-violet/50 hover:bg-violet/10"
            asChild
          >
            <a
              href="https://github.com/un4ckn0wl3z/dioprocess-private"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Github className="w-4 h-4" />
              GitHub
            </a>
          </Button>

          <Button
            size="sm"
            className="hidden sm:flex bg-violet hover:bg-violet/90"
            asChild
          >
            <Link href="/docs/getting-started">Get Started</Link>
          </Button>

          <Sheet open={open} onOpenChange={setOpen}>
            <SheetTrigger asChild className="md:hidden">
              <Button variant="ghost" size="icon">
                <Menu className="w-5 h-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="w-72 bg-background border-border">
              <div className="flex flex-col gap-4 mt-8">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setOpen(false)}
                    className="flex items-center gap-3 px-3 py-2 text-muted-foreground hover:text-foreground hover:bg-secondary/50 rounded-md transition-colors"
                  >
                    <item.icon className="w-5 h-5" />
                    {item.label}
                  </Link>
                ))}
                <div className="border-t border-border pt-4 mt-2">
                  <Button className="w-full bg-violet hover:bg-violet/90" asChild>
                    <Link href="/docs/getting-started" onClick={() => setOpen(false)}>
                      Get Started
                    </Link>
                  </Button>
                </div>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
