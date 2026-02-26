import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";
import { Badge } from "@/components/ui/badge";

export default function KernelInstallationPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">Driver Installation</h1>
        <p className="text-lg text-muted-foreground">
          Load the DioProcess kernel driver to enable Ring 0 and Ring -1 features.
        </p>
      </div>

      <WarningBox variant="danger" title="Prerequisites Required">
        Before installing the kernel driver, you MUST complete all prerequisite steps. 
        Failure to do so will result in installation failure or system instability.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Prerequisites</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline">Step 1</Badge>
              <h3 className="font-semibold">Disable Hyper-V</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              The bundled hypervisor conflicts with Hyper-V. Disable it and reboot.
            </p>
            <CodeBlock
              language="powershell"
              code={`bcdedit /set hypervisorlaunchtype off
# Reboot required after this command`}
            />
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline">Step 2</Badge>
              <h3 className="font-semibold">Disable Secure Boot</h3>
            </div>
            <p className="text-sm text-muted-foreground">
              Access your BIOS/UEFI settings during boot and disable Secure Boot. 
              The exact steps vary by manufacturer.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline">Step 3</Badge>
              <h3 className="font-semibold">Disable Driver Protections</h3>
            </div>
            <ul className="text-sm text-muted-foreground space-y-2">
              <li>
                <strong>Driver Signature Enforcement:</strong> Enable test signing mode
                <CodeBlock
                  language="powershell"
                  code={`bcdedit /set testsigning on
# Reboot required`}
                  className="mt-2"
                />
              </li>
              <li className="mt-3">
                <strong>Vulnerable Driver Blocklist:</strong> Windows Security → Device Security → Core Isolation → Disable
              </li>
              <li>
                <strong>Memory Integrity (HVCI):</strong> Disable if enabled in Core Isolation settings
              </li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Installation Methods</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-green-500/30 bg-green-500/10">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-green-400">Signed Driver (Recommended)</h3>
              <Badge variant="outline" className="border-green-500/30 text-green-400">Default</Badge>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              Use the title bar &quot;Install Driver&quot; button. This downloads and installs 
              a signed driver that works without test signing mode.
            </p>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">Manual Installation (sc.exe)</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-3">
              For development or custom builds, use the Service Control Manager:
            </p>
            <CodeBlock
              language="batch"
              code={`:: Create the driver service
sc create DioProcess type= kernel binPath= "C:\\path\\to\\DioProcess.sys"

:: Start the driver
sc start DioProcess

:: Stop the driver
sc stop DioProcess

:: Delete the service
sc delete DioProcess`}
            />
          </div>

          <div className="p-4 rounded-lg border border-yellow-500/30 bg-yellow-500/10">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-yellow-400">KDU / KDMapper</h3>
              <Badge variant="outline" className="border-yellow-500/30 text-yellow-400">-alldrv flag</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              With the <code>-alldrv</code> CLI flag, additional installation methods are available 
              that use vulnerable driver exploits. These are for advanced users only.
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Verification</h2>
        <p className="text-muted-foreground">
          After installation, verify the driver is loaded:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• The UI title bar will show driver status (green indicator)</li>
          <li>• Kernel features in context menus will be enabled (not grayed out)</li>
          <li>• The Hypervisor tab will show &quot;Running&quot; status</li>
        </ul>
        
        <CodeBlock
          language="powershell"
          code={`# Check if driver is loaded
sc query DioProcess

# Expected output when running:
# STATE: 4  RUNNING`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Troubleshooting</h2>
        
        <div className="space-y-4">
          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Driver fails to start</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Check that Hyper-V is disabled: <code>bcdedit | findstr hypervisor</code></li>
              <li>• Verify test signing is enabled: <code>bcdedit | findstr testsigning</code></li>
              <li>• Check install log: <code>%LOCALAPPDATA%\DioProcess\install.log</code></li>
            </ul>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">Access denied errors</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Run DioProcess as Administrator</li>
              <li>• Check that the driver service was created successfully</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg border border-border/50 bg-card/50">
            <h3 className="font-semibold mb-2">System instability</h3>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Stop the driver: <code>sc stop DioProcess</code></li>
              <li>• Delete the service: <code>sc delete DioProcess</code></li>
              <li>• Reboot if necessary</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Debug Logging</h2>
        <p className="text-muted-foreground">
          The driver logs operations via <code>KdPrint()</code>. Use DbgView (SysInternals) 
          to capture debug output:
        </p>
        <CodeBlock
          language="text"
          code={`DioProcess: Windows Build: 10.0 (Build 26100)
DioProcess: Driver loaded successfully
DioProcess: Hypervisor initialized
DioProcess: Device \\\\Device\\\\DioProcess created`}
        />
      </section>
    </div>
  );
}
