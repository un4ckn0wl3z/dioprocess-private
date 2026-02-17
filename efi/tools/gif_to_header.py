#!/usr/bin/env python3
"""
gif_to_header.py — Convert GIF animation to C header for UEFI boot screen.

Converts a GIF file to raw BGRA32 frames embedded as C arrays, compatible with
UEFI Graphics Output Protocol (GOP) BltBuffer format.

Usage:
    python gif_to_header.py input.gif -o Animation.h
    python gif_to_header.py input.gif > Animation.h

Requirements:
    pip install Pillow

Output format:
    - BGRA32 pixel format (matches GOP PixelBlueGreenRedReserved8BitPerColor)
    - Per-frame delay values in milliseconds
    - Frames as UINT8 arrays

Example workflow:
    1. Create/download a GIF (recommended max 256x256 @ 10-15 fps)
    2. python gif_to_header.py logo.gif -o Animation.h
    3. Copy Animation.h to efi/DioProcessEfi/
    4. Build with: build -a X64 -t VS2022 -p DioProcessEfi/DioProcessEfi.dsc -b RELEASE
"""

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
    sys.exit(1)


def extract_frames(gif_path: Path, standalone_frames: bool = False) -> list[tuple[bytes, int]]:
    """
    Extract all frames from a GIF as BGRA32 bytes.
    
    Properly handles GIF disposal methods to avoid frame ghosting.
    
    Args:
        gif_path: Path to GIF file
        standalone_frames: If True, treat each frame as a complete image
                          (no compositing/accumulation). Use for 3D renders
                          or GIFs where each frame is a full image.
    
    Returns list of (frame_bytes, delay_ms) tuples.
    """
    frames = []
    
    with Image.open(gif_path) as img:
        # Get dimensions
        width, height = img.size
        
        # Track canvas state for proper disposal handling
        canvas = Image.new("RGBA", (width, height), (0, 0, 0, 255))
        last_canvas = canvas.copy()
        
        try:
            frame_num = 0
            while True:
                # Get frame delay (in ms, default 100ms if not specified)
                delay = img.info.get("duration", 100)
                if delay <= 0:
                    delay = 100
                
                # Get disposal method (0=unspecified, 1=none, 2=background, 3=previous)
                disposal = img.info.get("disposal", 0)
                
                # For standalone frames mode, always start fresh
                if standalone_frames:
                    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 255))
                    disposal = 2  # Force clear after each frame
                
                # Save canvas state before this frame (for disposal method 3)
                if disposal == 3:
                    restore_canvas = last_canvas.copy()
                else:
                    restore_canvas = None
                
                # Save current state for next iteration's "previous" reference
                last_canvas = canvas.copy()
                
                # Convert frame to RGBA
                frame = img.convert("RGBA")
                
                # Composite frame onto canvas at the correct position
                # Some GIFs have frames at offsets
                paste_box = (0, 0)
                if hasattr(img, 'tile') and img.tile:
                    try:
                        # tile format: [(decoder, (x0, y0, x1, y1), offset, params), ...]
                        tile = img.tile[0]
                        if len(tile) >= 2 and isinstance(tile[1], tuple) and len(tile[1]) >= 2:
                            paste_box = (tile[1][0], tile[1][1])
                    except (IndexError, TypeError):
                        pass
                
                # Paste with alpha mask for transparency
                canvas.paste(frame, paste_box, frame)
                
                # Convert to BGRA32 for GOP
                # PIL gives RGBA (R, G, B, A), GOP wants BGRA (B, G, R, Reserved)
                rgba_data = canvas.tobytes()
                bgra_data = bytearray(len(rgba_data))
                
                for i in range(0, len(rgba_data), 4):
                    r, g, b, a = rgba_data[i:i+4]
                    bgra_data[i] = b      # Blue
                    bgra_data[i+1] = g    # Green
                    bgra_data[i+2] = r    # Red
                    bgra_data[i+3] = 0    # Reserved (GOP ignores alpha)
                
                frames.append((bytes(bgra_data), delay))
                
                # Apply disposal method AFTER capturing this frame
                if disposal == 2:
                    # Restore to background (clear canvas to black)
                    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 255))
                elif disposal == 3 and restore_canvas is not None:
                    # Restore to previous frame
                    canvas = restore_canvas
                # disposal 0 or 1: leave canvas as-is for next frame
                
                # Move to next frame
                frame_num += 1
                img.seek(img.tell() + 1)
                
        except EOFError:
            pass  # End of frames
    
    return frames, width, height


def generate_header(frames: list[tuple[bytes, int]], width: int, height: int, output_name: str) -> str:
    """Generate C header content from frame data."""
    
    lines = []
    lines.append("/** @file")
    lines.append(f"  Auto-generated animation data from GIF.")
    lines.append(f"  Generated by gif_to_header.py")
    lines.append(f"")
    lines.append(f"  Dimensions: {width}x{height}")
    lines.append(f"  Frames: {len(frames)}")
    lines.append(f"  Format: BGRA32 (GOP PixelBlueGreenRedReserved8BitPerColor)")
    lines.append("**/")
    lines.append("")
    lines.append("#ifndef ANIMATION_H_")
    lines.append("#define ANIMATION_H_")
    lines.append("")
    lines.append("#include <Uefi.h>")
    lines.append("")
    lines.append(f"#define ANIMATION_WIDTH       {width}")
    lines.append(f"#define ANIMATION_HEIGHT      {height}")
    lines.append(f"#define ANIMATION_FRAME_COUNT {len(frames)}")
    lines.append(f"#define ANIMATION_FRAME_SIZE  ({width} * {height} * 4)")
    lines.append("")
    
    # Frame delays array
    lines.append("// Frame delays in milliseconds")
    lines.append("STATIC CONST UINT32 AnimationDelays[] = {")
    delay_values = ", ".join(str(delay) for _, delay in frames)
    lines.append(f"    {delay_values}")
    lines.append("};")
    lines.append("")
    
    # Frame data arrays
    for i, (frame_data, _) in enumerate(frames):
        lines.append(f"// Frame {i}: {len(frame_data)} bytes")
        lines.append(f"STATIC CONST UINT8 AnimationFrame{i}[] = {{")
        
        # Output bytes in rows of 16
        for row_start in range(0, len(frame_data), 16):
            row_end = min(row_start + 16, len(frame_data))
            row_bytes = frame_data[row_start:row_end]
            hex_values = ", ".join(f"0x{b:02X}" for b in row_bytes)
            comma = "," if row_end < len(frame_data) else ""
            lines.append(f"    {hex_values}{comma}")
        
        lines.append("};")
        lines.append("")
    
    # Frame pointer array
    lines.append("// Array of frame pointers for indexed access")
    lines.append("STATIC CONST UINT8* CONST AnimationFrames[] = {")
    frame_ptrs = ", ".join(f"AnimationFrame{i}" for i in range(len(frames)))
    lines.append(f"    {frame_ptrs}")
    lines.append("};")
    lines.append("")
    lines.append("#endif // ANIMATION_H_")
    lines.append("")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Convert GIF to C header for UEFI boot animation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("input", type=Path, help="Input GIF file")
    parser.add_argument("-o", "--output", type=Path, help="Output header file (default: stdout)")
    parser.add_argument("--max-frames", type=int, default=100, 
                        help="Maximum frames to extract (default: 100)")
    parser.add_argument("--standalone-frames", action="store_true",
                        help="Treat each frame as a complete image (no compositing). "
                             "Use for 3D renders or GIFs where frames don't accumulate.")
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Loading GIF: {args.input}", file=sys.stderr)
    if args.standalone_frames:
        print(f"[*] Mode: Standalone frames (no compositing)", file=sys.stderr)
    frames, width, height = extract_frames(args.input, standalone_frames=args.standalone_frames)
    
    if len(frames) > args.max_frames:
        print(f"[!] Truncating to {args.max_frames} frames (was {len(frames)})", file=sys.stderr)
        frames = frames[:args.max_frames]
    
    print(f"[*] Extracted {len(frames)} frames @ {width}x{height}", file=sys.stderr)
    
    total_bytes = sum(len(f[0]) for f in frames)
    print(f"[*] Total data size: {total_bytes:,} bytes ({total_bytes / 1024:.1f} KB)", file=sys.stderr)
    
    header_content = generate_header(frames, width, height, args.output.stem if args.output else "Animation")
    
    if args.output:
        args.output.write_text(header_content, encoding="utf-8")
        print(f"[+] Wrote: {args.output}", file=sys.stderr)
    else:
        print(header_content)
    
    print(f"[+] Done! Copy the header to efi/DioProcessEfi/ and rebuild.", file=sys.stderr)


if __name__ == "__main__":
    main()
