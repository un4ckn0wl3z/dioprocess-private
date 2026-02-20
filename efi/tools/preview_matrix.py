#!/usr/bin/env python3
"""
preview_glitch.py — Console preview of the glitch boot animation.
Matches the logic in Graphics.c exactly. Run in Windows Terminal.

Usage:
    python preview_matrix.py
    python preview_matrix.py --width 80 --height 24 --duration 5
"""

import argparse
import os
import random
import sys
import time

# ── Branding ──────────────────────────────────────────────────────────────────
TITLE = "DAMNED SOFTWARE"
MOTTO = "deeper than ring zero"

# ── ANSI ──────────────────────────────────────────────────────────────────────
RESET    = "\033[0m"
CLEAR    = "\033[2J\033[H"
HIDE_CUR = "\033[?25l"
SHOW_CUR = "\033[?25h"

def fg(r, g, b): return f"\033[38;2;{r};{g};{b}m"
def bold():      return "\033[1m"

GLITCH_COLORS = [
    fg(80,  80,  80),    # DARKGRAY
    fg(0,   180, 0),     # GREEN
    fg(0,   255, 70),    # LIGHTGREEN
    fg(0,   200, 200),   # CYAN
    fg(0,   255, 255),   # LIGHTCYAN
    fg(200, 200, 200),   # LIGHTGRAY
    fg(255, 255, 255),   # WHITE
]
ATTR_TITLE = fg(255, 255, 255) + bold()
ATTR_MOTTO = fg(0,   255, 70)
ATTR_BLANK = fg(0,   0,   0)

GLITCH_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789!@#$%^&*<>|/\\{}[]+-=~_"
)

FRAME_MS = 40   # ms

def run(width, height, fps, duration):
    rng = random.Random(1337)

    # Bar state
    bars = []   # list of dicts: row, col, width, color, life

    title_row = height // 2 - 1
    motto_row = title_row + 1
    title_col = max(0, (width - len(TITLE)) // 2)
    motto_col = max(0, (width - len(MOTTO)) // 2)

    frame_delay = FRAME_MS / 1000.0
    total_frames = int(duration * 1000 / FRAME_MS)

    sys.stdout.write(HIDE_CUR)
    try:
        for fi in range(total_frames):
            intensity = rng.randint(0, 9)

            # Spawn bars
            if   intensity < 2: new_n = rng.randint(0, 1)
            elif intensity < 7: new_n = rng.randint(1, 3)
            else:               new_n = rng.randint(3, 6)

            for _ in range(new_n):
                row   = rng.randint(0, height - 1)
                w     = rng.randint(4, width)
                col   = rng.randint(0, max(0, width - w))
                color = rng.choice(GLITCH_COLORS)
                life  = rng.randint(1, 3)
                bars.append({"row": row, "col": col, "w": w,
                              "color": color, "life": life})
                if len(bars) > 8:
                    bars.pop(0)

            # Build screen buffer: list of rows, each a list of (color, char)
            buf = [[(ATTR_BLANK, ' ')] * width for _ in range(height)]

            # Draw bars
            new_bars = []
            for b in bars:
                row = b["row"]
                max_w = (width - 1) if row == height - 1 else width
                c = b["col"]
                w = min(b["w"], max(0, max_w - c))
                for j in range(w):
                    if c + j < width:
                        ch = rng.choice(GLITCH_CHARS)
                        buf[row][c + j] = (b["color"], ch)
                b["life"] -= 1
                if b["life"] > 0:
                    new_bars.append(b)
            bars = new_bars

            # Scatter noise on heavy frames
            if intensity >= 7:
                for _ in range(rng.randint(4, 20)):
                    r = rng.randint(0, height - 1)
                    c = rng.randint(0, width - 2)
                    buf[r][c] = (rng.choice(GLITCH_COLORS), rng.choice(GLITCH_CHARS))

            # Title
            corrupt = intensity >= 8 and rng.randint(0, 2) == 0
            for j, ch in enumerate(TITLE):
                tc = title_col + j
                if 0 <= tc < width:
                    if corrupt and rng.randint(0, 4) == 0:
                        buf[title_row][tc] = (rng.choice(GLITCH_COLORS), rng.choice(GLITCH_CHARS))
                    else:
                        shimmer = ATTR_TITLE if (fi // 4) % 2 == 0 else ATTR_MOTTO
                        buf[title_row][tc] = (shimmer, ch)

            # Motto
            for j, ch in enumerate(MOTTO):
                mc = motto_col + j
                if 0 <= mc < width:
                    buf[motto_row][mc] = (ATTR_MOTTO, ch)

            # Render
            out = [CLEAR]
            for row in buf:
                line = ""
                prev_color = None
                for color, ch in row:
                    if color != prev_color:
                        line += color
                        prev_color = color
                    line += ch
                out.append(line + RESET)
            sys.stdout.write("\n".join(out))
            sys.stdout.flush()

            time.sleep(frame_delay)

    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(RESET + SHOW_CUR + "\n")
        sys.stdout.flush()


def main():
    try:
        term_cols, term_rows = os.get_terminal_size()
    except OSError:
        term_cols, term_rows = 80, 24

    parser = argparse.ArgumentParser(description="Glitch boot animation preview")
    parser.add_argument("--width",    type=int, default=min(term_cols, 120))
    parser.add_argument("--height",   type=int, default=min(term_rows - 1, 30))
    parser.add_argument("--duration", type=float, default=5.0)
    args = parser.parse_args()

    run(args.width, args.height, 25, args.duration)


if __name__ == "__main__":
    main()
