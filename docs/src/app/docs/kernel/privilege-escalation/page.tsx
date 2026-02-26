import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function PrivilegeEscalationPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Privilege Escalation</h1>
        <p className="text-lg text-muted-foreground">
          Enable all 40 Windows privileges for any process via direct 
          <code className="text-violet mx-1">_TOKEN</code> structure modification.
        </p>
      </div>

      <WarningBox variant="danger" title="Security Research Only">
        Token privilege escalation bypasses Windows security restrictions. 
        Use only on test systems with proper authorization.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          Windows privileges control what operations a process can perform. By directly 
          modifying the <code>_TOKEN.Privileges</code> structure in kernel memory, DioProcess 
          can grant all privileges to any process, bypassing <code>AdjustTokenPrivileges</code> restrictions.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Call <code>GetWindowsVersion()</code> to detect current Windows build</li>
          <li><code>PsLookupProcessByProcessId()</code> to get EPROCESS pointer</li>
          <li><code>PsReferencePrimaryToken(eProcess)</code> to get TOKEN pointer</li>
          <li>Calculate privilege address: <code>TOKEN + PROCESS_PRIVILEGE_OFFSET</code> (0x40)</li>
          <li>Set all privilege bitmasks to 0xFF:
            <CodeBlock
              language="cpp"
              code={`tokenPrivs->Present[0-4] = 0xff;
tokenPrivs->Enabled[0-4] = 0xff;
tokenPrivs->EnabledByDefault[0-4] = 0xff;`}
              className="mt-2"
            />
          </li>
          <li><code>PsDereferencePrimaryToken(pToken)</code></li>
          <li><code>ObDereferenceObject(eProcess)</code></li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Privileges Enabled</h2>
        <p className="text-muted-foreground">
          All 40 Windows privileges are enabled, including:
        </p>
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-violet">High-Impact Privileges</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• <code>SeDebugPrivilege</code> — Debug any process</li>
              <li>• <code>SeLoadDriverPrivilege</code> — Load kernel drivers</li>
              <li>• <code>SeTcbPrivilege</code> — Act as part of OS</li>
              <li>• <code>SeAssignPrimaryTokenPrivilege</code> — Assign tokens</li>
              <li>• <code>SeTakeOwnershipPrivilege</code> — Take ownership</li>
            </ul>
          </div>
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2 text-violet">Other Key Privileges</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• <code>SeBackupPrivilege</code> — Bypass file ACLs (read)</li>
              <li>• <code>SeRestorePrivilege</code> — Bypass file ACLs (write)</li>
              <li>• <code>SeImpersonatePrivilege</code> — Impersonate tokens</li>
              <li>• <code>SeCreateTokenPrivilege</code> — Create tokens</li>
              <li>• <code>SeSecurityPrivilege</code> — Manage audit logs</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Structure Offset</h2>
        <p className="text-muted-foreground">
          The token privilege offset is <strong>0x40</strong> across all Windows 10/11 versions — 
          this is a very stable offset.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Ensure the kernel driver is loaded</li>
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous</strong></li>
          <li>Select <strong>⚡ Enable All Privileges</strong></li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Grant unrestricted access</strong> — Without restarting the process</li>
          <li>• <strong>Bypass privilege checks</strong> — For security research</li>
          <li>• <strong>Test privilege escalation detection</strong> — EDR/SIEM testing</li>
          <li>• <strong>Enable SeDebugPrivilege</strong> — For process manipulation</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Item</th>
                <th className="text-left py-3 px-4 font-semibold">Location</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Rust function</td>
                <td className="py-3 px-4 font-mono text-violet">callback::enable_all_privileges(pid)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">IOCTL</td>
                <td className="py-3 px-4 font-mono">IOCTL_DIOPROCESS_ENABLE_PRIVILEGES (0x807)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
