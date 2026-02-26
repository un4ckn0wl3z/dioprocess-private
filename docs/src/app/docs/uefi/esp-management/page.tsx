import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function EspManagementPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">ESP Management</h1>
          <Badge variant="default" className="bg-purple-600">EFI</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Install, remove, and manage the DioProcess EFI driver on the EFI System Partition.
        </p>
      </div>

      <WarningBox variant="danger" title="Boot Modification Warning">
        Modifying the ESP can render your system unbootable. Always have recovery media 
        ready before making changes. Test on VMs first.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The EFI System Partition (ESP) contains all UEFI boot files. DioProcess installs 
          its EFI driver to the ESP and creates a boot entry that loads before Windows.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Installation Location</h2>
        <CodeBlock
          language="text"
          code={`EFI System Partition (typically S: when mounted)
└── EFI/
    ├── Microsoft/
    │   └── Boot/
    │       └── bootmgfw.efi  (Windows Boot Manager)
    └── DioProcess/
        └── DioProcessEfi.efi  (DioProcess bootkit)`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Installation Process</h2>
        <ol className="space-y-3 text-muted-foreground list-decimal list-inside">
          <li><strong>Mount ESP</strong> — Uses <code>mountvol /s</code> to mount ESP to a temporary drive letter</li>
          <li><strong>Copy EFI driver</strong> — Copies <code>DioProcessEfi.efi</code> to <code>ESP:\EFI\DioProcess\</code></li>
          <li><strong>Create boot entry</strong> — Uses <code>bcdedit</code> to copy Windows Boot Manager entry</li>
          <li><strong>Set path</strong> — Points the new entry to DioProcess EFI driver</li>
          <li><strong>Set as default</strong> — Optionally sets DioProcess as the default boot entry</li>
          <li><strong>Unmount ESP</strong> — Cleans up the temporary mount</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Rust API</h2>
        <CodeBlock
          language="rust"
          filename="crates/uefi/src/esp.rs"
          code={`use crate::UefiError;
use std::process::Command;

/// Install EFI driver to ESP
pub fn install_efi_driver(efi_path: &str) -> Result<(), UefiError> {
    // 1. Mount ESP
    let esp_drive = mount_esp()?;
    
    // 2. Create directory
    let dest_dir = format!("{}\\\\EFI\\\\DioProcess", esp_drive);
    std::fs::create_dir_all(&dest_dir)?;
    
    // 3. Copy EFI file
    let dest_path = format!("{}\\\\DioProcessEfi.efi", dest_dir);
    std::fs::copy(efi_path, &dest_path)?;
    
    // 4. Create boot entry (copy from bootmgr)
    let output = Command::new("bcdedit")
        .args(["/copy", "{bootmgr}", "/d", "DioProcess"])
        .output()?;
    
    // Parse GUID from output
    let guid = parse_guid_from_bcdedit(&output.stdout)?;
    
    // 5. Set the path to our EFI driver
    Command::new("bcdedit")
        .args(["/set", &guid, "path", "\\\\EFI\\\\DioProcess\\\\DioProcessEfi.efi"])
        .output()?;
    
    // 6. Unmount ESP
    unmount_esp(&esp_drive)?;
    
    Ok(())
}

/// Remove EFI driver from ESP
pub fn remove_efi_driver() -> Result<(), UefiError> {
    // 1. Mount ESP
    let esp_drive = mount_esp()?;
    
    // 2. Remove EFI file
    let efi_path = format!("{}\\\\EFI\\\\DioProcess\\\\DioProcessEfi.efi", esp_drive);
    std::fs::remove_file(&efi_path).ok();
    std::fs::remove_dir(format!("{}\\\\EFI\\\\DioProcess", esp_drive)).ok();
    
    // 3. Remove boot entry
    let entries = list_boot_entries()?;
    for entry in entries {
        if entry.description == "DioProcess" {
            Command::new("bcdedit")
                .args(["/delete", &entry.guid])
                .output()?;
        }
    }
    
    // 4. Unmount ESP
    unmount_esp(&esp_drive)?;
    
    Ok(())
}

fn mount_esp() -> Result<String, UefiError> {
    // mountvol /s assigns the ESP to the next available drive letter
    Command::new("mountvol")
        .args(["S:", "/s"])
        .output()?;
    Ok("S:".to_string())
}

fn unmount_esp(drive: &str) -> Result<(), UefiError> {
    Command::new("mountvol")
        .args([drive, "/d"])
        .output()?;
    Ok(())
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Boot Order</h2>
        <p className="text-muted-foreground">
          After installation, the boot order becomes:
        </p>
        <ol className="space-y-2 text-muted-foreground list-decimal list-inside">
          <li>DioProcess EFI driver loads</li>
          <li>Driver hooks ExitBootServices</li>
          <li>Driver reads NVRAM configuration</li>
          <li>Driver applies patches (DSE/KPP bypass)</li>
          <li>Driver chainloads Windows Boot Manager</li>
          <li>Windows continues normal boot</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          EFI driver installation is managed from the <strong>title bar</strong>:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Install EFI</strong> button — Downloads from GitHub (or browse local with <code>-debug</code> flag)</li>
          <li>• <strong>Uninstall EFI</strong> button — Removes driver and boot entry</li>
          <li>• <strong>Status indicator</strong> — Shows if EFI driver is currently installed</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Manual Installation</h2>
        <p className="text-muted-foreground">
          For manual installation from an elevated command prompt:
        </p>
        <CodeBlock
          language="batch"
          code={`:: Mount ESP
mountvol S: /s

:: Create directory
mkdir S:\\EFI\\DioProcess

:: Copy EFI driver
copy DioProcessEfi.efi S:\\EFI\\DioProcess\\

:: Create boot entry
bcdedit /copy {bootmgr} /d "DioProcess"
:: Note the GUID that is output, e.g., {12345678-...}

:: Set the path
bcdedit /set {12345678-...} path \\EFI\\DioProcess\\DioProcessEfi.efi

:: (Optional) Set as default
bcdedit /default {12345678-...}

:: Unmount ESP
mountvol S: /d`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Manual Removal</h2>
        <CodeBlock
          language="batch"
          code={`:: List current boot entries
bcdedit /enum firmware

:: Find the DioProcess entry GUID and delete it
bcdedit /delete {12345678-...}

:: Mount ESP and remove files
mountvol S: /s
rmdir /s /q S:\\EFI\\DioProcess
mountvol S: /d`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Recovery</h2>
        <p className="text-muted-foreground">
          If the system fails to boot after installing the EFI driver:
        </p>
        <ol className="space-y-2 text-muted-foreground list-decimal list-inside">
          <li>Boot from Windows installation media or recovery drive</li>
          <li>Select &quot;Repair your computer&quot; → Command Prompt</li>
          <li>Run: <code>bcdedit /delete {`{dioprocess-guid}`}</code></li>
          <li>Remove EFI files: <code>rd /s /q S:\EFI\DioProcess</code></li>
          <li>Reboot normally</li>
        </ol>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Testing with QEMU</h2>
        <p className="text-muted-foreground">
          Test the EFI driver in a VM before installing on real hardware:
        </p>
        <CodeBlock
          language="powershell"
          code={`# Use the provided QEMU script
cd efi\\tools
.\\Run-Qemu.ps1 -EfiPath ..\\..\\DioProcessEfi.efi

# Or manually:
qemu-system-x86_64 -bios OVMF.fd -hda win10.qcow2 \\
    -drive file=fat:rw:esp/,format=raw,media=disk`}
        />
      </section>
    </div>
  );
}
