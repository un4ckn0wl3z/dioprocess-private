import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";

export default function RegisterHooksPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Register Interception</h1>
          <Badge variant="outline">Ring -1</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Intercept and modify CPU control register access (CR0, CR3, CR4, DR*) from the 
          hypervisor.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Control registers govern critical CPU behavior. The hypervisor can trap access to 
          these registers, allowing interception and modification of OS behavior invisibly.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Intercepted Registers</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Register</th>
                <th className="text-left py-2 px-3 font-semibold">Purpose</th>
                <th className="text-left py-2 px-3 font-semibold">Use Case</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CR0</td>
                <td className="py-2 px-3 text-muted-foreground">System control (WP, PE, PG)</td>
                <td className="py-2 px-3 text-muted-foreground">Disable write protection</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CR3</td>
                <td className="py-2 px-3 text-muted-foreground">Page table base (PDBR)</td>
                <td className="py-2 px-3 text-muted-foreground">Track context switches</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">CR4</td>
                <td className="py-2 px-3 text-muted-foreground">Extended features (SMEP, SMAP)</td>
                <td className="py-2 px-3 text-muted-foreground">Disable SMEP/SMAP</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">DR0-DR3</td>
                <td className="py-2 px-3 text-muted-foreground">Debug breakpoint addresses</td>
                <td className="py-2 px-3 text-muted-foreground">Invisible breakpoints</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">DR6</td>
                <td className="py-2 px-3 text-muted-foreground">Debug status</td>
                <td className="py-2 px-3 text-muted-foreground">Hide debug events</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">DR7</td>
                <td className="py-2 px-3 text-muted-foreground">Debug control</td>
                <td className="py-2 px-3 text-muted-foreground">Invisible debug control</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CR0 Write Protection Bypass</h2>
        <p className="text-muted-foreground">
          CR0.WP (Write Protect) prevents ring 0 code from writing to read-only pages. 
          The hypervisor can intercept CR0 writes to keep WP disabled:
        </p>
        <CodeBlock
          language="cpp"
          filename="CR0 WP Bypass"
          code={`// When guest writes CR0, hypervisor intercepts
VOID VmExitHandler_MovToCr0(PVCPU_CONTEXT Vcpu, ULONG64 NewValue) {
    // Force WP bit to 0 (disable write protection)
    NewValue &= ~CR0_WP;
    
    // Allow other bits through
    Vcpu->GuestCr0 = NewValue;
    
    // Update shadow CR0 (what OS thinks it set)
    Vcpu->ShadowCr0 = NewValue | CR0_WP;  // Lie to OS
}

// When guest reads CR0, return shadow value
VOID VmExitHandler_MovFromCr0(PVCPU_CONTEXT Vcpu) {
    // Return shadow (with WP bit showing as set)
    Vcpu->Rax = Vcpu->ShadowCr0;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">CR3 Context Tracking</h2>
        <p className="text-muted-foreground">
          Track process context switches by intercepting CR3 loads:
        </p>
        <CodeBlock
          language="cpp"
          filename="CR3 Tracking"
          code={`// Map of CR3 values to process info
std::map<ULONG64, ProcessInfo> Cr3ToProcess;

VOID VmExitHandler_MovToCr3(PVCPU_CONTEXT Vcpu, ULONG64 NewCr3) {
    ULONG64 OldCr3 = Vcpu->GuestCr3;
    
    // Log context switch
    if (Cr3ToProcess.count(NewCr3)) {
        auto& Proc = Cr3ToProcess[NewCr3];
        LogEvent("Switched to PID %d (%s)", Proc.Pid, Proc.Name);
        
        // Apply per-process hooks if registered
        if (HasHooksForProcess(Proc.Pid)) {
            ApplyEptHooks(Proc.Pid);
        }
    }
    
    // Allow CR3 load to proceed
    Vcpu->GuestCr3 = NewCr3;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Invisible Debug Registers</h2>
        <p className="text-muted-foreground">
          Set hardware breakpoints that are invisible to the guest OS:
        </p>
        <CodeBlock
          language="cpp"
          filename="Hidden DR Breakpoints"
          code={`// Hypervisor maintains its own debug register state
struct HiddenDebugState {
    ULONG64 Dr0, Dr1, Dr2, Dr3;  // Breakpoint addresses
    ULONG64 Dr6;                  // Status
    ULONG64 Dr7;                  // Control
};

HiddenDebugState HvDebugState;
HiddenDebugState GuestDebugState;  // What OS set

// When guest reads DR, return guest's (shadow) value
VOID VmExitHandler_MovFromDr(PVCPU_CONTEXT Vcpu, ULONG DrNum) {
    switch (DrNum) {
        case 0: Vcpu->Rax = GuestDebugState.Dr0; break;
        case 1: Vcpu->Rax = GuestDebugState.Dr1; break;
        // ... etc
    }
}

// When guest writes DR, save to guest state but don't apply
VOID VmExitHandler_MovToDr(PVCPU_CONTEXT Vcpu, ULONG DrNum, ULONG64 Value) {
    // Save what guest thinks it set
    switch (DrNum) {
        case 0: GuestDebugState.Dr0 = Value; break;
        // ... etc
    }
    
    // Actual hardware breakpoints are HvDebugState, not visible to guest
    // Guest's breakpoints are never actually set in hardware
}

// Set hypervisor's own invisible breakpoint
VOID HvSetBreakpoint(ULONG Slot, ULONG64 Address, ULONG Type) {
    switch (Slot) {
        case 0: HvDebugState.Dr0 = Address; break;
        // ... etc
    }
    
    // Configure DR7 for the breakpoint
    HvDebugState.Dr7 |= (1 << (Slot * 2));  // Enable
    HvDebugState.Dr7 |= (Type << (16 + Slot * 4));  // Condition
    
    // Apply to actual hardware
    ApplyHvDebugState();
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">IOCTLs</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">IOCTL</th>
                <th className="text-left py-2 px-3 font-semibold">Code</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_SET_BREAKPOINT</td>
                <td className="py-2 px-3">0x820</td>
                <td className="py-2 px-3 text-muted-foreground">Set invisible breakpoint</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_CLEAR_BREAKPOINT</td>
                <td className="py-2 px-3">0x821</td>
                <td className="py-2 px-3 text-muted-foreground">Remove breakpoint</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_DISABLE_SMEP</td>
                <td className="py-2 px-3">0x822</td>
                <td className="py-2 px-3 text-muted-foreground">Disable SMEP via CR4 intercept</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">HV_SET_CR3_CALLBACK</td>
                <td className="py-2 px-3">0x823</td>
                <td className="py-2 px-3 text-muted-foreground">Register CR3 change callback</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Disable write protection</strong> — Allow writing to read-only kernel memory</li>
          <li>• <strong>Process tracking</strong> — Monitor context switches via CR3</li>
          <li>• <strong>Invisible breakpoints</strong> — Debug without detection</li>
          <li>• <strong>Disable SMEP/SMAP</strong> — Execute user pages from kernel</li>
          <li>• <strong>Anti-anti-debug</strong> — Hide debug state from targets</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Considerations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Timing attacks can detect CR exit latency</li>
          <li>• Side-channel analysis of instruction timing</li>
          <li>• CPUID leaf analysis for hypervisor detection</li>
          <li>• TSC offset manipulation detection</li>
        </ul>
      </section>
    </div>
  );
}
