import Link from "next/link";
import { Github, Heart } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-border/40 bg-background/50">
      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="md:col-span-2">
            <Link href="/" className="flex items-center gap-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet to-purple-700 flex items-center justify-center">
                <span className="text-white font-bold">D</span>
              </div>
              <span className="font-bold text-lg">
                Dio<span className="text-violet">Process</span>
              </span>
            </Link>
            <p className="text-sm text-muted-foreground max-w-md">
              Advanced Windows process monitor and security research tool. Built with Rust and Dioxus for maximum performance and safety.
            </p>
          </div>

          <div>
            <h4 className="font-semibold mb-4">Documentation</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>
                <Link href="/docs/getting-started" className="hover:text-violet transition-colors">
                  Getting Started
                </Link>
              </li>
              <li>
                <Link href="/docs/usermode" className="hover:text-violet transition-colors">
                  Usermode Features
                </Link>
              </li>
              <li>
                <Link href="/docs/kernel" className="hover:text-violet transition-colors">
                  Kernel Driver
                </Link>
              </li>
              <li>
                <Link href="/docs/hypervisor" className="hover:text-violet transition-colors">
                  Hypervisor (Ring -1)
                </Link>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold mb-4">Resources</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>
                <a
                  href="https://github.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 hover:text-violet transition-colors"
                >
                  <Github className="w-4 h-4" />
                  GitHub
                </a>
              </li>
              <li>
                <Link href="/docs/api-reference" className="hover:text-violet transition-colors">
                  API Reference
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-border/40 mt-8 pt-8 flex flex-col sm:flex-row justify-between items-center gap-4">
          <p className="text-sm text-muted-foreground">
            © {new Date().getFullYear()} DioProcess. MIT Licensed.
          </p>
          <p className="text-sm text-muted-foreground flex items-center gap-1">
            Built with <Heart className="w-4 h-4 text-red-500 fill-red-500" /> using Rust & Dioxus
          </p>
        </div>
      </div>
    </footer>
  );
}
