import { WarningBox } from "@/components/warning-box";

export default function TokenTheftPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Token Theft</h1>
        <p className="text-lg text-muted-foreground">
          Steal and impersonate process tokens to launch new processes under 
          different security contexts.
        </p>
      </div>

      <WarningBox variant="danger" title="Privilege Escalation">
        Token theft can be used to escalate privileges. Only use on systems you own 
        or have explicit permission to test.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Algorithm</h2>
        <p className="text-muted-foreground">
          The <code className="text-violet">steal_token()</code> function performs the following steps:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li><code>OpenProcess</code> with <code>PROCESS_QUERY_LIMITED_INFORMATION</code></li>
          <li><code>OpenProcessToken</code> to obtain the target&apos;s primary token</li>
          <li><code>DuplicateTokenEx(SecurityAnonymous, TokenPrimary)</code> to create a usable copy</li>
          <li>Enable <code>SeAssignPrimaryTokenPrivilege</code> via <code>AdjustTokenPrivileges</code></li>
          <li><code>ImpersonateLoggedOnUser</code> to impersonate the token</li>
          <li><code>CreateProcessAsUserW</code> to spawn a new process under the stolen token</li>
          <li><code>RevertToSelf</code> to restore the original security context</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Usage</h2>
        <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
          <li>Right-click on a process in the Process tab</li>
          <li>Navigate to <strong>Miscellaneous → Steal Token</strong></li>
          <li>In the Token Thief window:
            <ul className="ml-6 mt-1 space-y-1">
              <li>• Source process name and PID are displayed</li>
              <li>• Select the executable to launch under the stolen token</li>
              <li>• Optionally provide command line arguments</li>
            </ul>
          </li>
          <li>Click <strong>Steal Token</strong></li>
          <li>Success shows the new process PID/TID</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Common Targets</h2>
        <p className="text-muted-foreground">
          Useful token sources for privilege escalation research:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>SYSTEM processes</strong> — winlogon.exe, lsass.exe, services.exe</li>
          <li>• <strong>Service accounts</strong> — Processes running as LocalService or NetworkService</li>
          <li>• <strong>Elevated processes</strong> — Any process running with administrator privileges</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Required Privileges</h2>
        <p className="text-muted-foreground">
          Token theft requires the following privileges (typically available to administrators):
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <code className="text-violet">SeDebugPrivilege</code> — To open processes with limited access</li>
          <li>• <code className="text-violet">SeAssignPrimaryTokenPrivilege</code> — To assign tokens to new processes</li>
          <li>• <code className="text-violet">SeImpersonatePrivilege</code> — To impersonate tokens</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Implementation</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-semibold">Item</th>
                <th className="text-left py-3 px-4 font-semibold">Value</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">File</td>
                <td className="py-3 px-4 font-mono text-violet">crates/misc/src/token.rs</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">Function</td>
                <td className="py-3 px-4 font-mono text-violet">steal_token(pid, exe_path, args)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-3 px-4">UI Component</td>
                <td className="py-3 px-4 font-mono text-violet">token_thief_window.rs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
