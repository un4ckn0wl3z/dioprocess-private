#!/usr/bin/env python3
"""
generate_test_gif.py — Generate a test GIF for boot animation testing.

Creates a simple animated GIF with the DioProcess violet theme for testing
the boot animation system without needing external assets.

Usage:
    python generate_test_gif.py                    # Default: spinning square
    python generate_test_gif.py -o custom.gif      # Custom output path
    python generate_test_gif.py --style pulse      # Pulsing circle
    python generate_test_gif.py --style spinner    # Loading spinner
    python generate_test_gif.py --size 128         # 128x128 pixels

Requirements:
    pip install Pillow
"""

import argparse
import math
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Error: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
    sys.exit(1)


# DioProcess theme colors
VIOLET = (139, 92, 246)      # #8b5cf6
DARK_VIOLET = (91, 33, 182)  # #5b21b6
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)


def generate_spinner(size: int = 64, frames: int = 12) -> list:
    """Generate a loading spinner animation."""
    images = []
    center = size // 2
    radius = size // 3
    dot_radius = size // 12
    
    for frame in range(frames):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw dots in a circle
        for i in range(8):
            angle = (2 * math.pi * i / 8) - (math.pi / 2)
            x = center + int(radius * math.cos(angle))
            y = center + int(radius * math.sin(angle))
            
            # Fade based on position relative to current frame
            offset = (frame * 8 // frames)
            brightness = ((i - offset) % 8) / 8
            
            r = int(VIOLET[0] * brightness + 30)
            g = int(VIOLET[1] * brightness + 20)
            b = int(VIOLET[2] * brightness + 40)
            
            draw.ellipse(
                [x - dot_radius, y - dot_radius, x + dot_radius, y + dot_radius],
                fill=(r, g, b, 255)
            )
        
        images.append(img)
    
    return images, 80  # 80ms per frame


def generate_pulse(size: int = 64, frames: int = 20) -> list:
    """Generate a pulsing circle animation."""
    images = []
    center = size // 2
    max_radius = size // 2 - 4
    min_radius = size // 4
    
    for frame in range(frames):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Calculate radius using sine wave
        t = frame / frames
        radius = min_radius + (max_radius - min_radius) * (0.5 + 0.5 * math.sin(2 * math.pi * t))
        
        # Draw glow layers
        for i in range(3):
            glow_radius = radius + (3 - i) * 3
            alpha = 80 - i * 25
            draw.ellipse(
                [center - glow_radius, center - glow_radius,
                 center + glow_radius, center + glow_radius],
                fill=(VIOLET[0], VIOLET[1], VIOLET[2], alpha)
            )
        
        # Draw main circle
        draw.ellipse(
            [center - radius, center - radius, center + radius, center + radius],
            fill=VIOLET + (255,)
        )
        
        images.append(img)
    
    return images, 50  # 50ms per frame


def generate_rotate(size: int = 64, frames: int = 16) -> list:
    """Generate a rotating square animation."""
    images = []
    center = size // 2
    square_size = size // 3
    
    for frame in range(frames):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Calculate rotation angle
        angle = (360 * frame / frames)
        
        # Create rotated square
        square = Image.new("RGBA", (square_size * 2, square_size * 2), (0, 0, 0, 0))
        sq_draw = ImageDraw.Draw(square)
        
        # Draw square with gradient-like effect
        sq_draw.rectangle(
            [square_size // 2, square_size // 2,
             square_size + square_size // 2, square_size + square_size // 2],
            fill=VIOLET + (255,),
            outline=DARK_VIOLET + (255,),
            width=2
        )
        
        # Rotate and paste
        rotated = square.rotate(angle, resample=Image.BICUBIC, expand=False)
        paste_x = center - square_size
        paste_y = center - square_size
        img.paste(rotated, (paste_x, paste_y), rotated)
        
        images.append(img)
    
    return images, 60  # 60ms per frame


def generate_text(size: int = 128, frames: int = 10) -> list:
    """Generate DioProcess text fade animation."""
    images = []
    
    for frame in range(frames):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Fade in/out cycle
        t = frame / frames
        alpha = int(255 * (0.5 + 0.5 * math.sin(2 * math.pi * t)))
        
        # Draw "DP" text (simple pixel art style)
        # D
        draw.rectangle([size//4 - 15, size//3, size//4 - 10, size*2//3], 
                      fill=VIOLET + (alpha,))
        draw.arc([size//4 - 15, size//3, size//4 + 5, size*2//3], 
                -90, 90, fill=VIOLET + (alpha,), width=5)
        
        # P  
        draw.rectangle([size//2 + 5, size//3, size//2 + 10, size*2//3],
                      fill=VIOLET + (alpha,))
        draw.arc([size//2 + 5, size//3, size//2 + 25, size//2 + 5],
                -90, 90, fill=VIOLET + (alpha,), width=5)
        
        images.append(img)
    
    return images, 100


def generate_bars(size: int = 64, frames: int = 15) -> list:
    """Generate equalizer-style bars animation."""
    images = []
    bar_count = 5
    bar_width = size // (bar_count * 2)
    max_height = size * 2 // 3
    
    for frame in range(frames):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        for i in range(bar_count):
            # Each bar has different phase
            t = (frame / frames + i * 0.2) % 1.0
            height = int(max_height * (0.3 + 0.7 * abs(math.sin(2 * math.pi * t))))
            
            x = size // (bar_count + 1) * (i + 1) - bar_width // 2
            y = size - (size - max_height) // 2 - height
            
            # Color gradient based on height
            intensity = height / max_height
            r = int(DARK_VIOLET[0] + (VIOLET[0] - DARK_VIOLET[0]) * intensity)
            g = int(DARK_VIOLET[1] + (VIOLET[1] - DARK_VIOLET[1]) * intensity)
            b = int(DARK_VIOLET[2] + (VIOLET[2] - DARK_VIOLET[2]) * intensity)
            
            draw.rectangle(
                [x, y, x + bar_width, size - (size - max_height) // 2],
                fill=(r, g, b, 255)
            )
        
        images.append(img)
    
    return images, 70


STYLES = {
    'spinner': generate_spinner,
    'pulse': generate_pulse,
    'rotate': generate_rotate,
    'text': generate_text,
    'bars': generate_bars,
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate test GIF for boot animation",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("test_animation.gif"),
        help="Output GIF path (default: test_animation.gif)"
    )
    parser.add_argument(
        "-s", "--size", type=int, default=64,
        help="Animation size in pixels (default: 64)"
    )
    parser.add_argument(
        "--style", choices=list(STYLES.keys()), default="spinner",
        help=f"Animation style (default: spinner)"
    )
    parser.add_argument(
        "--list-styles", action="store_true",
        help="List available animation styles"
    )
    
    args = parser.parse_args()
    
    if args.list_styles:
        print("Available styles:")
        print("  spinner  - Loading spinner with rotating dots")
        print("  pulse    - Pulsing circle with glow effect")
        print("  rotate   - Rotating square")
        print("  text     - Fading 'DP' text")
        print("  bars     - Equalizer bars")
        return
    
    print(f"[*] Generating '{args.style}' animation @ {args.size}x{args.size}", file=sys.stderr)
    
    generator = STYLES[args.style]
    frames, delay = generator(args.size)
    
    print(f"[*] Generated {len(frames)} frames @ {delay}ms each", file=sys.stderr)
    
    # Save as GIF
    frames[0].save(
        args.output,
        save_all=True,
        append_images=frames[1:],
        duration=delay,
        loop=0,
        disposal=2  # Clear previous frame
    )
    
    print(f"[+] Saved: {args.output}", file=sys.stderr)
    print(f"[*] Total animation time: {len(frames) * delay}ms", file=sys.stderr)
    print(f"", file=sys.stderr)
    print(f"Next steps:", file=sys.stderr)
    print(f"  1. Preview:  python simulate_boot.py {args.output}", file=sys.stderr)
    print(f"  2. Convert:  python gif_to_header.py {args.output} -o ../DioProcessEfi/Animation.h", file=sys.stderr)


if __name__ == "__main__":
    main()
