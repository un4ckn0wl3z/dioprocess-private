import { Badge } from "@/components/ui/badge";

export default function ProcessHidingPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Process & Driver Hiding</h1>
        <p className="text-lg text-muted-foreground">
          Hide processes and kernel drivers from Ring 0 enumeration via EPT manipulation.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Process Hiding</h2>
        <p className="text-muted-foreground">
          Hide processes from Ring 0 enumeration tools. The process continues to run but 
          becomes invisible to kernel-level process enumeration.
        </p>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-2">IOCTLs</h3>
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>• <code className="text-violet">HV_PROTECT_PROCESS</code> (0x830) — Hide process</li>
            <li>• <code className="text-violet">HV_UNPROTECT_PROCESS</code> (0x831) — Unhide process</li>
            <li>• <code className="text-violet">HV_IS_PROCESS_PROTECTED</code> (0x832) — Check if hidden</li>
            <li>• <code className="text-violet">HV_LIST_PROTECTED</code> (0x833) — List hidden processes</li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Driver Hiding</h2>
        <p className="text-muted-foreground">
          Hide kernel drivers from Ring 0 enumeration. Useful for hiding the DioProcess 
          driver itself or other drivers from detection.
        </p>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50">
          <h3 className="font-semibold mb-2">IOCTLs</h3>
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>• <code className="text-violet">HV_HIDE_DRIVER</code> (0x834) — Hide driver by name</li>
            <li>• <code className="text-violet">HV_UNHIDE_DRIVER</code> (0x835) — Unhide driver</li>
            <li>• <code className="text-violet">HV_IS_DRIVER_HIDDEN</code> (0x836) — Check if hidden</li>
            <li>• <code className="text-violet">HV_REMOVE_HIDDEN_DRIVER</code> (0x837) — Remove from hidden list</li>
            <li>• <code className="text-violet">HV_CLEAR_HIDDEN_DRIVERS</code> (0x838) — Clear all hidden</li>
            <li>• <code className="text-violet">HV_LIST_HIDDEN_DRIVERS</code> (0x839) — List hidden drivers</li>
          </ul>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Maximum of 16 drivers can be hidden simultaneously (<code>MAX_HIDDEN_DRIVERS</code>).
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">How It Works</h2>
        <p className="text-muted-foreground">
          The hypervisor uses EPT (Extended Page Tables) to manipulate memory visibility:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• EPT hooks intercept memory reads to kernel structures</li>
          <li>• Hidden entries are filtered from enumeration results</li>
          <li>• The actual process/driver continues to execute normally</li>
          <li>• Only Ring 0 enumeration is affected — Ring -1 can still see everything</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <p className="text-muted-foreground">
          Access via the <strong>Hypervisor</strong> tab:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Process Hiding</strong> section — Select process, click Hide/Unhide</li>
          <li>• <strong>Driver Hiding</strong> section — Enter driver name (e.g., &quot;dpdrv.sys&quot;), click Hide</li>
          <li>• View currently hidden items in the respective lists</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Structures</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Structure</th>
                <th className="text-left py-3 px-4 font-semibold">Fields</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">HideDriverRequest</td>
                <td className="py-3 px-4 text-muted-foreground">DriverName[64]</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">DriverHiddenResponse</td>
                <td className="py-3 px-4 text-muted-foreground">IsHidden, HiddenCount</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4 font-mono text-violet">HiddenDriverListResponse</td>
                <td className="py-3 px-4 text-muted-foreground">Count, DriverNames[16][64]</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
