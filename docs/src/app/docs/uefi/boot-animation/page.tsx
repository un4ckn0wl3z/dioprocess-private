import { Badge } from "@/components/ui/badge";
import { CodeBlock } from "@/components/code-block";
import { WarningBox } from "@/components/warning-box";

export default function BootAnimationPage() {
  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-4">
          <h1 className="text-4xl font-bold">Boot Animation</h1>
          <Badge variant="default" className="bg-purple-600">EFI</Badge>
        </div>
        <p className="text-lg text-muted-foreground">
          Customize the animated boot screen displayed by the UEFI DXE driver during the 
          5-second delay before chainloading Windows.
        </p>
      </div>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Overview</h2>
        <p className="text-muted-foreground">
          The EFI driver displays a custom animated boot screen using the UEFI Graphics Output 
          Protocol (GOP). Animation frames are pre-converted at build time and embedded in the 
          EFI binary for maximum performance.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Technical Details</h2>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Format:</strong> BGRA32 (matches GOP <code>PixelBlueGreenRedReserved8BitPerColor</code>)</li>
          <li>• <strong>Pre-converted:</strong> No runtime GIF decoding, frames stored as raw pixels</li>
          <li>• <strong>Display:</strong> Centered on screen, loops for 5 seconds</li>
          <li>• <strong>Fallback:</strong> Text-only display if GOP unavailable</li>
          <li>• <strong>Recommended:</strong> Max 256x256 resolution, 10-15 fps</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Converting a GIF Animation</h2>
        <p className="text-muted-foreground">
          Use the provided Python tool to convert a GIF to the C header format:
        </p>
        <CodeBlock
          language="bash"
          filename="Convert GIF"
          code={`# Install requirements
pip install Pillow

# Convert GIF to C header
python efi/tools/gif_to_header.py your_animation.gif -o efi/DioProcessEfi/Animation.h

# Rebuild EFI driver
cd efi
build -a X64 -t VS2022 -p DioProcessEfi/DioProcessEfi.dsc -b RELEASE`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Animation.h Format</h2>
        <CodeBlock
          language="c"
          filename="Animation.h (generated)"
          code={`#ifndef ANIMATION_H
#define ANIMATION_H

#define ANIMATION_WIDTH  128
#define ANIMATION_HEIGHT 128
#define ANIMATION_FRAME_COUNT 12
#define ANIMATION_FRAME_DELAY_MS 83  // ~12 fps

// Frame data: BGRA32 format, row-major order
static const UINT8 AnimationFrame0[] = {
    0x00, 0x00, 0x00, 0xFF,  // Pixel 0: BGRA
    0x8B, 0x5C, 0xF6, 0xFF,  // Pixel 1: Violet
    // ... (WIDTH * HEIGHT * 4 bytes per frame)
};

static const UINT8 AnimationFrame1[] = { /* ... */ };
// ... more frames

static const UINT8* AnimationFrames[] = {
    AnimationFrame0,
    AnimationFrame1,
    // ... all frames
};

#endif`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Graphics Implementation</h2>
        <CodeBlock
          language="c"
          filename="Graphics.c (excerpt)"
          code={`EFI_STATUS PlayAnimation(VOID) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;
    EFI_STATUS Status;
    
    // 1. Locate GOP protocol
    Status = gBS->LocateProtocol(
        &gEfiGraphicsOutputProtocolGuid,
        NULL,
        (VOID**)&Gop
    );
    if (EFI_ERROR(Status)) {
        // Fallback to text mode
        return ShowTextBanner();
    }
    
    // 2. Get screen dimensions
    UINTN ScreenWidth = Gop->Mode->Info->HorizontalResolution;
    UINTN ScreenHeight = Gop->Mode->Info->VerticalResolution;
    
    // 3. Calculate centered position
    UINTN X = (ScreenWidth - ANIMATION_WIDTH) / 2;
    UINTN Y = (ScreenHeight - ANIMATION_HEIGHT) / 2;
    
    // 4. Animation loop (5 seconds)
    UINTN TotalFrames = (5000 / ANIMATION_FRAME_DELAY_MS);
    for (UINTN i = 0; i < TotalFrames; i++) {
        UINTN FrameIndex = i % ANIMATION_FRAME_COUNT;
        
        // 5. Blit frame to screen
        Gop->Blt(
            Gop,
            (EFI_GRAPHICS_OUTPUT_BLT_PIXEL*)AnimationFrames[FrameIndex],
            EfiBltBufferToVideo,
            0, 0,           // Source X, Y
            X, Y,           // Dest X, Y
            ANIMATION_WIDTH,
            ANIMATION_HEIGHT,
            0               // Delta (row stride)
        );
        
        // 6. Wait for next frame
        gBS->Stall(ANIMATION_FRAME_DELAY_MS * 1000);  // microseconds
    }
    
    return EFI_SUCCESS;
}`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Creating Custom Animations</h2>
        <p className="text-muted-foreground">
          Tips for creating effective boot animations:
        </p>
        <ul className="space-y-2 text-muted-foreground">
          <li>• <strong>Keep it small</strong> — Large animations increase EFI binary size</li>
          <li>• <strong>Simple loops</strong> — 8-16 frames is usually sufficient</li>
          <li>• <strong>Use transparency wisely</strong> — Alpha channel is preserved</li>
          <li>• <strong>Test on real hardware</strong> — Some UEFI implementations have limitations</li>
        </ul>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Alternative: Matrix Animation</h2>
        <p className="text-muted-foreground">
          The repo includes tools to generate Matrix-style falling code animation:
        </p>
        <CodeBlock
          language="bash"
          code={`# Generate Matrix animation
python efi/tools/gen_matrix_animation.py -o efi/DioProcessEfi/Animation.h

# Preview in console
python efi/tools/preview_matrix.py`}
        />
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-bold">Default Placeholder</h2>
        <p className="text-muted-foreground">
          The default <code>Animation.h</code> contains a simple 2-frame blinking violet 
          square that demonstrates the animation system without adding significant binary size.
        </p>
      </section>
    </div>
  );
}
