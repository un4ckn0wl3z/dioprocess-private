import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function SmmQemuTestingPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold mb-4">QEMU Testing</h1>
        <p className="text-lg text-muted-foreground">
          Pre-built OVMF firmware with embedded DioProcess SMM/DXE drivers ships in{" "}
          <code className="text-violet">efi/ovmf/</code>. Run under QEMU to test SMM code safely
          without risking real hardware.
        </p>
      </div>

      <WarningBox variant="info" title="Always Test Here First">
        Every SMM change should be validated in QEMU before touching real firmware. Bricked
        motherboards require an SPI flash programmer to recover.
      </WarningBox>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Quick Start</h2>
        <CodeBlock
          language="batch"
          code={`cd efi\\ovmf
run_qemu.bat`}
        />
        <p className="text-muted-foreground">
          The batch script launches QEMU with SMM support enabled, using the bundled OVMF firmware
          that already contains <code>DioProcessSmm.efi</code> and <code>DioProcessDxe.efi</code>.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Expected Serial Output</h2>
        <p className="text-muted-foreground">
          On boot, both drivers announce themselves on the serial console:
        </p>
        <CodeBlock
          language="text"
          code={`=[ DioProcess DXE ]=
[ DXE ] EFI_MM_COMMUNICATION2_PROTOCOL discovered
=[ DioProcess SMM ]=
=[ Ring -2 Memory Operations ]=
[ SMM ] SMM driver invoked by SMM IPL, initializing...
[ SMM ] SMM driver has been initialized`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Directory Contents</h2>
        <div className="p-4 rounded-lg border border-border/50 bg-card/50 font-mono text-sm">
          <pre className="text-muted-foreground">{`efi/ovmf/
├── OVMF_CODE.fd     # OVMF firmware with embedded SMM/DXE drivers
├── OVMF_VARS.fd     # NVRAM variables (persist across QEMU runs)
└── run_qemu.bat     # QEMU launch script with SMM support`}</pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">QEMU Launch Script</h2>
        <p className="text-muted-foreground">
          The <code>run_qemu.bat</code> script sets up SMM-capable QEMU with the following flags:
        </p>
        <CodeBlock
          language="batch"
          code={`qemu-system-x86_64.exe ^
  -machine q35,smm=on,accel=tcg ^
  -global driver=cfi.pflash01,property=secure,value=on ^
  -drive if=pflash,format=raw,unit=0,file=OVMF_CODE.fd,readonly=on ^
  -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd ^
  -serial stdio ^
  -m 4G ^
  -cpu qemu64,+smep,+smap ^
  -smp cores=2`}
        />
        <ul className="space-y-2 text-muted-foreground mt-4">
          <li>
            • <code>smm=on</code> — enables the emulated SMM controller
          </li>
          <li>
            • <code>secure=on</code> on pflash — locks OVMF_CODE.fd against runtime writes
          </li>
          <li>
            • <code>-serial stdio</code> — routes serial output to your terminal
          </li>
          <li>
            • <code>accel=tcg</code> — TCG software emulation (KVM/WHPX cannot emulate SMM)
          </li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Building OVMF from Source</h2>
        <p className="text-muted-foreground">
          To rebuild the OVMF image with your own changes to the SMM/DXE drivers:
        </p>
        <CodeBlock
          language="batch"
          code={`# Requires EDK2 toolchain at C:\\edk2
cd C:\\edk2
edksetup.bat

# Build SMM driver
build -a X64 -t VS2022 -p D:/dio/dioprocess-private/efi/DioProcessSmm/DioProcessSmm.dsc -b RELEASE

# Build DXE driver
build -a X64 -t VS2022 -p D:/dio/dioprocess-private/efi/DioProcessDxe/DioProcessDxe.dsc -b RELEASE

# Rebuild OVMF with embedded drivers (SMM_REQUIRE forces SMM inclusion)
build -DSMM_REQUIRE

# Output firmware lives at:
# C:\\edk2\\Build\\OvmfX64\\RELEASE_VS2022\\FV\\OVMF_CODE.fd`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Windows Guest Testing</h2>
        <p className="text-muted-foreground">
          To exercise the full stack (usermode → kernel driver → SMM), install Windows 10 22H2 in
          the QEMU guest, then install the DioProcess kernel driver as usual. The kernel driver
          reads the NVRAM buffer address and triggers SMIs — everything works the same as on real
          hardware, just slower due to TCG emulation.
        </p>
        <p className="text-muted-foreground">
          A WHPX-accelerated QEMU script (<code>run_qemu_whpx.bat</code>) is also included for
          faster Windows install — however, WHPX cannot emulate SMM, so switch back to the
          TCG-based <code>run_qemu.bat</code> for actual SMM testing.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Real Hardware Testing</h2>
        <WarningBox variant="danger" title="Extreme Risk">
          Testing SMM on real hardware requires flashing modified UEFI firmware. Do NOT do this
          without a hardware SPI recovery path.
        </WarningBox>
        <ul className="space-y-2 text-muted-foreground mt-4">
          <li>
            • <strong>Brick risk</strong> — incorrect flash can make the motherboard unbootable
          </li>
          <li>
            • <strong>Intel Boot Guard</strong> — many modern systems verify firmware signatures
            and refuse unsigned images
          </li>
          <li>
            • <strong>Recovery</strong> — requires an SPI flash programmer (CH341A + SOIC clip) to
            restore a good image
          </li>
          <li>
            • <strong>Recommendation</strong> — QEMU for development; real hardware only on
            expendable test machines with backed-up firmware
          </li>
        </ul>
      </section>
    </div>
  );
}
