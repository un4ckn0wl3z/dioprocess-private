#!/usr/bin/env python3
"""
gen_matrix_animation.py — Matrix rain boot animation for Damned Software.

Generates a Matrix-style digital rain animation with "DAMNED SOFTWARE" branding
and a rootkit/bootkit motto. Outputs Animation.h directly in BGRA32 format for
the UEFI DXE driver (no GIF intermediate — no color quantization).

Usage:
    python gen_matrix_animation.py -o ../DioProcessEfi/Animation.h
    python gen_matrix_animation.py --preview     # also saves matrix_preview.gif

Requirements:
    pip install Pillow
"""

import argparse
import math
import random
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Error: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
    sys.exit(1)

# ── Canvas ────────────────────────────────────────────────────────────────────
WIDTH  = 256
HEIGHT = 144    # 16:9 widescreen — good for text
FPS    = 20     # 50 ms per frame
FRAMES = 30     # 1.5 s loop (repeats ~3× during the 5 s EFI delay)
DELAY  = 1000 // FPS  # ms

# ── Branding ──────────────────────────────────────────────────────────────────
TITLE = "DAMNED SOFTWARE"

# Pick your motto:
MOTTO = "deeper than ring zero"
# Alternatives:
#   "boot earlier. patch everything."
#   "your kernel doesn't know we're here"
#   "ring -1 or nothing"
#   "where kernels fear to tread"

# ── Palette ───────────────────────────────────────────────────────────────────
C_BG     = (0,   0,   0,   255)
C_HEAD   = (200, 255, 200, 255)   # leading char — near-white green
C_BRIGHT = (0,   255, 70,  255)   # fresh trail
C_MID    = (0,   180, 50,  200)
C_DIM    = (0,   80,  20,  140)
C_TITLE  = (255, 255, 255, 255)   # white title text
C_MOTTO  = (0,   200, 70,  255)   # green motto text

# ── Grid ──────────────────────────────────────────────────────────────────────
CHAR_W = 8
CHAR_H = 12
COLS   = WIDTH  // CHAR_W   # 32 columns
ROWS   = HEIGHT // CHAR_H   # 12 rows

# ASCII characters that look "matrix-like" — avoids font compatibility issues
MATRIX_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789!@#$%^&*<>|/\\{}[]+-=~_"
)


# ── Font helpers ───────────────────────────────────────────────────────────────
def _try_font(name: str, size: int):
    try:
        return ImageFont.truetype(name, size)
    except (IOError, OSError, AttributeError):
        return None


def get_font(size: int):
    """Try common monospace fonts; fall back to PIL bitmap default."""
    candidates = [
        "cour.ttf",            # Courier New (Windows)
        "courbd.ttf",          # Courier New Bold
        "lucon.ttf",           # Lucida Console
        "consola.ttf",         # Consolas
        "consolab.ttf",        # Consolas Bold
        "DejaVuSansMono.ttf",
        "DejaVuSansMono-Bold.ttf",
        "UbuntuMono-Regular.ttf",
    ]
    for name in candidates:
        f = _try_font(name, size)
        if f is not None:
            return f
    return ImageFont.load_default()


# ── Rain simulation ────────────────────────────────────────────────────────────
class _Col:
    """One vertical column of falling characters."""

    def __init__(self, rng: random.Random):
        self.head  = rng.uniform(-ROWS, 0)   # current head row (float)
        self.speed = rng.uniform(0.25, 0.90) # rows per frame
        self.trail = rng.randint(4, ROWS)    # length of glowing trail
        self.chars = [rng.choice(MATRIX_CHARS) for _ in range(ROWS + 8)]
        self._rng  = rng

    def step(self):
        self.head += self.speed
        # Randomly mutate a character in the trail (the "glitching" effect)
        if self._rng.random() < 0.08:
            idx = self._rng.randint(0, len(self.chars) - 1)
            self.chars[idx] = self._rng.choice(MATRIX_CHARS)
        # Wrap when the whole trail has scrolled past the bottom
        if self.head - self.trail > ROWS + 2:
            self.head  = self._rng.uniform(-ROWS, -1)
            self.speed = self._rng.uniform(0.25, 0.90)
            self.trail = self._rng.randint(4, ROWS)


# ── Frame generation ──────────────────────────────────────────────────────────
def generate_frames() -> list:
    """Return list of PIL RGBA Images."""

    rng = random.Random(1337)   # fixed seed → deterministic animation

    rain_font  = get_font(CHAR_H - 1)  # ~11 px — fills the cell
    title_font = get_font(20)
    motto_font = get_font(11)

    cols = [_Col(rng) for _ in range(COLS)]

    # Pre-build scanline overlay (every other row slightly darkened)
    scanline = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    sl_draw  = ImageDraw.Draw(scanline)
    for y in range(0, HEIGHT, 2):
        sl_draw.line([(0, y), (WIDTH - 1, y)], fill=(0, 0, 0, 35))

    frames = []

    for fi in range(FRAMES):
        t   = fi / FRAMES   # 0.0 → 1.0
        img = Image.new("RGBA", (WIDTH, HEIGHT), C_BG)
        draw = ImageDraw.Draw(img)

        # ── Digital rain ──────────────────────────────────────────────────────
        for ci, col in enumerate(cols):
            col.step()
            x    = ci * CHAR_W
            head = col.head

            for row in range(ROWS + 1):
                dist = head - row           # 0 = at head, positive = behind head
                if dist < 0 or dist > col.trail:
                    continue

                y  = row * CHAR_H
                ch = col.chars[row % len(col.chars)]

                if dist < 0.8:
                    color = C_HEAD
                elif dist < 2.5:
                    color = C_BRIGHT
                elif dist < col.trail * 0.45:
                    a     = int(200 * (1 - dist / col.trail))
                    color = (C_MID[0], C_MID[1], C_MID[2], a)
                else:
                    a     = int(140 * (1 - dist / col.trail))
                    color = (C_DIM[0], C_DIM[1], C_DIM[2], a)

                draw.text((x, y), ch, font=rain_font, fill=color)

        # ── Scanline overlay ─────────────────────────────────────────────────
        img  = Image.alpha_composite(img, scanline)
        draw = ImageDraw.Draw(img)

        # ── Title ─────────────────────────────────────────────────────────────
        tb          = draw.textbbox((0, 0), TITLE, font=title_font)
        tw, th      = tb[2] - tb[0], tb[3] - tb[1]
        tx          = (WIDTH - tw) // 2
        ty          = HEIGHT // 2 - th - 10

        # Pulsing green glow behind the title
        glow_a = int(45 + 35 * math.sin(t * 2 * math.pi))
        for dx in range(-2, 3):
            for dy in range(-2, 3):
                if dx == 0 and dy == 0:
                    continue
                draw.text((tx + dx, ty + dy), TITLE,
                          font=title_font, fill=(0, 255, 80, glow_a))

        # Main title in white
        draw.text((tx, ty), TITLE, font=title_font, fill=C_TITLE)

        # ── Motto ─────────────────────────────────────────────────────────────
        mb  = draw.textbbox((0, 0), MOTTO, font=motto_font)
        mw  = mb[2] - mb[0]
        mx  = (WIDTH - mw) // 2
        my  = ty + th + 6
        draw.text((mx, my), MOTTO, font=motto_font, fill=C_MOTTO)

        frames.append(img)

    return frames


# ── Header generation ─────────────────────────────────────────────────────────
def generate_header(frames: list) -> str:
    """Encode frames as BGRA32 and emit Animation.h content."""

    lines = [
        "/** @file",
        "  Matrix rain animation — Damned Software boot screen.",
        "  Generated by gen_matrix_animation.py",
        "",
        f"  Dimensions: {WIDTH}x{HEIGHT}",
        f"  Frames: {len(frames)}",
        f"  FPS: {FPS}  Loop: {len(frames) * DELAY} ms",
        "  Format: BGRA32 (GOP PixelBlueGreenRedReserved8BitPerColor)",
        "**/",
        "",
        "#ifndef ANIMATION_H_",
        "#define ANIMATION_H_",
        "",
        "#include <Uefi.h>",
        "",
        f"#define ANIMATION_WIDTH       {WIDTH}",
        f"#define ANIMATION_HEIGHT      {HEIGHT}",
        f"#define ANIMATION_FRAME_COUNT {len(frames)}",
        f"#define ANIMATION_FRAME_SIZE  ({WIDTH} * {HEIGHT} * 4)",
        "",
        "// Frame delays in milliseconds",
        "STATIC CONST UINT32 AnimationDelays[] = {",
        f"    {', '.join(str(DELAY) for _ in frames)}",
        "};",
        "",
    ]

    for i, img in enumerate(frames):
        rgba  = img.tobytes()
        bgra  = bytearray(len(rgba))
        for j in range(0, len(rgba), 4):
            r, g, b, a = rgba[j:j+4]
            bgra[j]   = b   # Blue
            bgra[j+1] = g   # Green
            bgra[j+2] = r   # Red
            bgra[j+3] = 0   # Reserved

        lines.append(f"// Frame {i}: {len(bgra)} bytes")
        lines.append(f"STATIC CONST UINT8 AnimationFrame{i}[] = {{")
        for rs in range(0, len(bgra), 16):
            re       = min(rs + 16, len(bgra))
            row_hex  = ", ".join(f"0x{b:02X}" for b in bgra[rs:re])
            comma    = "," if re < len(bgra) else ""
            lines.append(f"    {row_hex}{comma}")
        lines.append("};")
        lines.append("")

    lines += [
        "// Array of frame pointers for indexed access",
        "STATIC CONST UINT8* CONST AnimationFrames[] = {",
        f"    {', '.join(f'AnimationFrame{i}' for i in range(len(frames)))}",
        "};",
        "",
        "#endif // ANIMATION_H_",
        "",
    ]

    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate Matrix rain animation for UEFI boot screen",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-o", "--output", type=Path,
                        help="Output Animation.h path (default: stdout)")
    parser.add_argument("--preview", action="store_true",
                        help="Also save matrix_preview.gif for visual inspection")
    args = parser.parse_args()

    print(f"[*] Generating {FRAMES} frames @ {WIDTH}x{HEIGHT} ({FPS} fps)...",
          file=sys.stderr)
    frames = generate_frames()
    print(f"[*] Generated {len(frames)} frames", file=sys.stderr)

    if args.preview:
        preview = Path("matrix_preview.gif")
        frames[0].save(
            preview,
            save_all=True,
            append_images=frames[1:],
            duration=DELAY,
            loop=0,
            optimize=False,
        )
        print(f"[*] Preview saved: {preview}", file=sys.stderr)

    raw_bytes = WIDTH * HEIGHT * 4 * len(frames)
    print(f"[*] Raw data: {raw_bytes:,} bytes ({raw_bytes / 1024:.0f} KB)",
          file=sys.stderr)

    header = generate_header(frames)

    if args.output:
        args.output.write_text(header, encoding="utf-8")
        print(f"[+] Wrote: {args.output}", file=sys.stderr)
    else:
        print(header)

    print("[+] Done! Rebuild EFI driver to apply.", file=sys.stderr)


if __name__ == "__main__":
    main()
