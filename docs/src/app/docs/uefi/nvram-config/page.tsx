import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function NvramConfigPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">NVRAM Configuration</h1>
          <Badge variant="default" className="bg-purple-600">EFI</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Configure UEFI bootkit behavior via NVRAM variables that persist across reboots.
        </p>
      </div>

      <WarningBox variant="warning" title="Requires Administrator + UEFI">
        NVRAM access requires administrator privileges and a UEFI system. 
        Legacy BIOS systems do not support NVRAM variables.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The DioProcess UEFI bootkit reads configuration from NVRAM variables at boot time. 
          These variables are set from the DioProcess UI and persist across reboots until 
          explicitly changed.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">NVRAM Variables</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Variable Name</th>
                <th className="text-left py-2 px-3 font-semibold">Type</th>
                <th className="text-left py-2 px-3 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">DioProcessDseBypass</td>
                <td className="py-2 px-3 text-muted-foreground">UINT8</td>
                <td className="py-2 px-3 text-muted-foreground">0 = DSE enabled, 1 = DSE bypassed</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3 font-mono text-xs">DioProcessKppBypass</td>
                <td className="py-2 px-3 text-muted-foreground">UINT8</td>
                <td className="py-2 px-3 text-muted-foreground">0 = KPP enabled, 1 = KPP bypassed</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          GUID: <code>{`{D10PR0C5-1337-4242-BEEF-CAFEBABE0001}`}</code>
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Rust API (uefi crate)</h2>
        <CodeBlock
          language="rust"
          filename="crates/uefi/src/nvram.rs"
          code={`use crate::{UefiConfig, UefiError};
use windows::Win32::System::SystemInformation::*;

/// Read current UEFI configuration from NVRAM
pub fn read_uefi_config() -> Result<UefiConfig, UefiError> {
    let dse = read_nvram_variable("DioProcessDseBypass")?;
    let kpp = read_nvram_variable("DioProcessKppBypass")?;
    
    Ok(UefiConfig {
        dse_bypass: dse != 0,
        kpp_bypass: kpp != 0,
    })
}

/// Write UEFI configuration to NVRAM (takes effect on next boot)
pub fn write_uefi_config(config: &UefiConfig) -> Result<(), UefiError> {
    write_nvram_variable(
        "DioProcessDseBypass",
        if config.dse_bypass { 1 } else { 0 }
    )?;
    
    write_nvram_variable(
        "DioProcessKppBypass", 
        if config.kpp_bypass { 1 } else { 0 }
    )?;
    
    Ok(())
}

fn read_nvram_variable(name: &str) -> Result<u8, UefiError> {
    let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut buffer = [0u8; 1];
    
    unsafe {
        GetFirmwareEnvironmentVariableW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PCWSTR::from_raw(GUID_WIDE.as_ptr()),
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32
        )
    };
    
    Ok(buffer[0])
}

fn write_nvram_variable(name: &str, value: u8) -> Result<(), UefiError> {
    // Enable SeSystemEnvironmentPrivilege first
    enable_privilege("SeSystemEnvironmentPrivilege")?;
    
    let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    
    unsafe {
        SetFirmwareEnvironmentVariableW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PCWSTR::from_raw(GUID_WIDE.as_ptr()),
            Some(&value as *const _ as *const _),
            1
        )
    }?;
    
    Ok(())
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">EFI Driver Reading</h2>
        <CodeBlock
          language="c"
          filename="Config.c"
          code={`EFI_GUID gDioProcessVarGuid = {
    0xD10PR0C5, 0x1337, 0x4242,
    {0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01}
};

EFI_STATUS ReadConfig(PDIOPROCESS_CONFIG Config) {
    UINTN DataSize = sizeof(UINT8);
    UINT8 Value;
    EFI_STATUS Status;
    
    // Read DSE bypass setting
    Status = gRT->GetVariable(
        L"DioProcessDseBypass",
        &gDioProcessVarGuid,
        NULL,
        &DataSize,
        &Value
    );
    Config->DseBypass = (Status == EFI_SUCCESS && Value == 1);
    
    // Read KPP bypass setting
    Status = gRT->GetVariable(
        L"DioProcessKppBypass",
        &gDioProcessVarGuid,
        NULL,
        &DataSize,
        &Value
    );
    Config->KppBypass = (Status == EFI_SUCCESS && Value == 1);
    
    return EFI_SUCCESS;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Access via UEFI Bootkit tab → Boot Patches section:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>DSE Bypass toggle</strong> — Enable/disable driver signature enforcement bypass</li>
          <li>• <strong>KPP Bypass toggle</strong> — Enable/disable PatchGuard bypass</li>
          <li>• <strong>Save button</strong> — Write settings to NVRAM</li>
          <li>• <strong>Status display</strong> — Shows current NVRAM values</li>
        </ul>
        <p className="text-muted-foreground mt-4">
          Changes take effect on the next boot — the EFI driver reads NVRAM during the 
          boot process before Windows loads.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Security Considerations</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• NVRAM variables persist until changed — settings survive OS reinstalls</li>
          <li>• Malicious software could read/write these variables</li>
          <li>• Consider clearing variables after testing</li>
          <li>• Secure Boot would prevent the EFI driver from loading</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Manual NVRAM Management</h2>
        <p className="text-muted-foreground">
          From an elevated command prompt:
        </p>
        <CodeBlock
          language="powershell"
          code={`# Check if UEFI (look for Firmware Type: UEFI)
msinfo32

# Variables are managed via SetFirmwareEnvironmentVariable API
# No built-in Windows command for custom NVRAM variables
# Use the DioProcess UI or write a custom tool`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Troubleshooting</h2>
        <div className="space-y-3 text-muted-foreground">
          <p><strong>Error: &quot;Access denied&quot;</strong></p>
          <p className="pl-4">• Run as administrator, ensure SeSystemEnvironmentPrivilege is available</p>
          
          <p><strong>Error: &quot;Not supported&quot;</strong></p>
          <p className="pl-4">• System is using Legacy BIOS, not UEFI</p>
          
          <p><strong>Settings don&apos;t apply after reboot</strong></p>
          <p className="pl-4">• EFI driver may not be installed or Secure Boot may be blocking it</p>
        </div>
      </section>
    </div>
  );
}
