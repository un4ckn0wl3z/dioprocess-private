#!/usr/bin/env python3
"""
simulate_boot.py — Preview UEFI boot animation without rebooting.

Simulates the DioProcess EFI boot screen by displaying the GIF animation
centered on a black window, exactly like it would appear at boot time.

Usage:
    python simulate_boot.py input.gif
    python simulate_boot.py input.gif --duration 5000
    python simulate_boot.py input.gif --resolution 1920x1080

Requirements:
    pip install Pillow

Controls:
    ESC / Q / Click = Exit
    SPACE = Pause/Resume
"""

import argparse
import sys
import tkinter as tk
from pathlib import Path

try:
    from PIL import Image, ImageTk
except ImportError:
    print("Error: Pillow not installed. Run: pip install Pillow", file=sys.stderr)
    sys.exit(1)


class BootAnimationSimulator:
    def __init__(self, gif_path: Path, duration_ms: int = 5000, resolution: tuple = None):
        self.gif_path = gif_path
        self.duration_ms = duration_ms
        self.frames = []
        self.delays = []
        self.current_frame = 0
        self.elapsed_ms = 0
        self.paused = False
        
        # Load GIF frames
        self._load_gif()
        
        # Create window
        self.root = tk.Tk()
        self.root.title(f"DioProcess Boot Simulator — {gif_path.name}")
        self.root.configure(bg='black')
        
        # Set resolution
        if resolution:
            self.screen_width, self.screen_height = resolution
        else:
            # Use 80% of actual screen size for preview
            self.screen_width = int(self.root.winfo_screenwidth() * 0.8)
            self.screen_height = int(self.root.winfo_screenheight() * 0.8)
        
        self.root.geometry(f"{self.screen_width}x{self.screen_height}")
        self.root.resizable(False, False)
        
        # Center the window on screen
        x = (self.root.winfo_screenwidth() - self.screen_width) // 2
        y = (self.root.winfo_screenheight() - self.screen_height) // 2
        self.root.geometry(f"+{x}+{y}")
        
        # Create canvas for animation
        self.canvas = tk.Canvas(
            self.root,
            width=self.screen_width,
            height=self.screen_height,
            bg='black',
            highlightthickness=0
        )
        self.canvas.pack()
        
        # Calculate center position
        self.center_x = (self.screen_width - self.anim_width) // 2
        self.center_y = (self.screen_height - self.anim_height) // 2
        
        # Create image display
        self.image_id = None
        self.photo_images = []  # Keep references to prevent GC
        self._prepare_frames()
        
        # Status text
        self.status_text = self.canvas.create_text(
            10, self.screen_height - 30,
            text="",
            fill='#8b5cf6',
            font=('Consolas', 10),
            anchor='sw'
        )
        
        self.info_text = self.canvas.create_text(
            self.screen_width - 10, self.screen_height - 30,
            text="[SPACE] Pause  [ESC] Exit",
            fill='#666666',
            font=('Consolas', 9),
            anchor='se'
        )
        
        # Bind keys
        self.root.bind('<Escape>', lambda e: self.root.destroy())
        self.root.bind('q', lambda e: self.root.destroy())
        self.root.bind('Q', lambda e: self.root.destroy())
        self.root.bind('<space>', self._toggle_pause)
        self.root.bind('<Button-1>', lambda e: self.root.destroy())
        
        # Start animation
        self._animate()
    
    def _load_gif(self):
        """Load GIF and extract frames."""
        print(f"[*] Loading: {self.gif_path}", file=sys.stderr)
        
        with Image.open(self.gif_path) as img:
            self.anim_width, self.anim_height = img.size
            
            # Create canvas for compositing
            canvas = Image.new("RGBA", (self.anim_width, self.anim_height), (0, 0, 0, 255))
            
            try:
                while True:
                    # Get frame delay
                    delay = img.info.get("duration", 100)
                    if delay <= 0:
                        delay = 100
                    
                    # Composite frame
                    frame = img.convert("RGBA")
                    canvas.paste(frame, (0, 0), frame)
                    
                    # Store copy
                    self.frames.append(canvas.copy())
                    self.delays.append(delay)
                    
                    img.seek(img.tell() + 1)
            except EOFError:
                pass
        
        print(f"[*] Loaded {len(self.frames)} frames @ {self.anim_width}x{self.anim_height}", file=sys.stderr)
        print(f"[*] Total animation time: {sum(self.delays)}ms", file=sys.stderr)
    
    def _prepare_frames(self):
        """Convert PIL images to Tk PhotoImages."""
        for frame in self.frames:
            photo = ImageTk.PhotoImage(frame)
            self.photo_images.append(photo)
        
        # Display first frame
        self.image_id = self.canvas.create_image(
            self.center_x, self.center_y,
            image=self.photo_images[0],
            anchor='nw'
        )
    
    def _toggle_pause(self, event=None):
        """Toggle pause state."""
        self.paused = not self.paused
    
    def _animate(self):
        """Animation loop."""
        if self.elapsed_ms >= self.duration_ms:
            # Animation complete
            self.canvas.itemconfig(
                self.status_text,
                text=f"✓ Animation complete ({self.duration_ms}ms)",
                fill='#22c55e'
            )
            return
        
        if not self.paused:
            # Update frame
            self.canvas.itemconfig(self.image_id, image=self.photo_images[self.current_frame])
            
            # Update status
            remaining = (self.duration_ms - self.elapsed_ms) // 1000
            self.canvas.itemconfig(
                self.status_text,
                text=f"Frame {self.current_frame + 1}/{len(self.frames)} | "
                     f"{self.elapsed_ms}ms / {self.duration_ms}ms | "
                     f"Boot in {remaining}s..."
            )
            
            # Get frame delay
            delay = self.delays[self.current_frame]
            
            # Cap delay to remaining time
            if self.elapsed_ms + delay > self.duration_ms:
                delay = self.duration_ms - self.elapsed_ms
            
            self.elapsed_ms += delay
            
            # Next frame
            self.current_frame = (self.current_frame + 1) % len(self.frames)
            
            # Schedule next update
            self.root.after(delay, self._animate)
        else:
            # Paused - show pause indicator
            self.canvas.itemconfig(
                self.status_text,
                text=f"⏸ PAUSED | Frame {self.current_frame + 1}/{len(self.frames)} | "
                     f"{self.elapsed_ms}ms / {self.duration_ms}ms",
                fill='#eab308'
            )
            self.root.after(100, self._animate)
    
    def run(self):
        """Start the simulator."""
        print(f"[*] Simulating boot animation ({self.duration_ms}ms)", file=sys.stderr)
        print(f"[*] Window: {self.screen_width}x{self.screen_height}", file=sys.stderr)
        print(f"[*] Animation position: ({self.center_x}, {self.center_y})", file=sys.stderr)
        print(f"[*] Press ESC or click to exit, SPACE to pause", file=sys.stderr)
        self.root.mainloop()


def parse_resolution(value: str) -> tuple:
    """Parse resolution string like '1920x1080'."""
    try:
        w, h = value.lower().split('x')
        return (int(w), int(h))
    except:
        raise argparse.ArgumentTypeError(f"Invalid resolution: {value} (use format: 1920x1080)")


def main():
    parser = argparse.ArgumentParser(
        description="Simulate DioProcess UEFI boot animation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("input", type=Path, help="Input GIF file")
    parser.add_argument(
        "-d", "--duration", type=int, default=5000,
        help="Animation duration in milliseconds (default: 5000)"
    )
    parser.add_argument(
        "-r", "--resolution", type=parse_resolution,
        help="Simulated screen resolution (default: 80%% of your screen)"
    )
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    simulator = BootAnimationSimulator(
        gif_path=args.input,
        duration_ms=args.duration,
        resolution=args.resolution
    )
    simulator.run()


if __name__ == "__main__":
    main()
