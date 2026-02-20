/** @file
  Glitch effect boot animation — Damned Software boot screen.

  Drives gST->ConOut with random horizontal noise bars, scatter chars,
  and occasional title corruption. ClearScreen + targeted draws keeps
  the firmware call count very low (~50 per frame vs 2000 for rain).

  Copyright (c) 2024, DioProcess. All rights reserved.
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>

#include "Graphics.h"

// ── Branding ──────────────────────────────────────────────────────────────────
STATIC CONST CHAR16 *TITLE = L"DAMNED SOFTWARE";
STATIC CONST CHAR16 *MOTTO = L"deeper than ring zero";
#define TITLE_LEN  15
#define MOTTO_LEN  21

// ── Timing ────────────────────────────────────────────────────────────────────
#define FRAME_MS   40       // ~25 fps

// ── Console caps ─────────────────────────────────────────────────────────────
#define MAX_COLS  200
#define MAX_ROWS   60

// ── Colour attributes ────────────────────────────────────────────────────────
#define ATTR_BLANK  EFI_TEXT_ATTR(EFI_BLACK,       EFI_BACKGROUND_BLACK)
#define ATTR_TITLE  EFI_TEXT_ATTR(EFI_WHITE,        EFI_BACKGROUND_BLACK)
#define ATTR_MOTTO  EFI_TEXT_ATTR(EFI_LIGHTGREEN,   EFI_BACKGROUND_BLACK)

#define GLITCH_COLOR_COUNT 7
STATIC CONST UINTN GLITCH_COLORS[GLITCH_COLOR_COUNT] = {
    EFI_TEXT_ATTR(EFI_DARKGRAY,    EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_GREEN,       EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_LIGHTGREEN,  EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_CYAN,        EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_LIGHTCYAN,   EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_LIGHTGRAY,   EFI_BACKGROUND_BLACK),
    EFI_TEXT_ATTR(EFI_WHITE,       EFI_BACKGROUND_BLACK),
};

// ── Glitch character set ──────────────────────────────────────────────────────
STATIC CONST CHAR16 GLITCH_CHARS[] =
    L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    L"0123456789!@#$%^&*<>|/\\{}[]+-=~_";
#define GLITCH_CHAR_COUNT  ((sizeof(GLITCH_CHARS) / sizeof(CHAR16)) - 1)

// ── LCG PRNG (no stdlib) ──────────────────────────────────────────────────────
STATIC UINT32 mRng = 1337;

STATIC UINT32
RngNext (VOID)
{
    mRng = mRng * 1664525u + 1013904223u;
    return mRng;
}

STATIC UINT32
RngRange (IN UINT32 Lo, IN UINT32 Hi)
{
    if (Hi <= Lo) return Lo;
    return Lo + (RngNext() % (Hi - Lo + 1));
}

// ── Console size ──────────────────────────────────────────────────────────────
STATIC UINTN mNumCols;
STATIC UINTN mNumRows;

// ── String buffer for bar content ─────────────────────────────────────────────
STATIC CHAR16 mLineBuf[MAX_COLS + 1];

STATIC VOID
FillGlitchStr (IN UINTN Len)
{
    UINTN i;
    if (Len > MAX_COLS) Len = MAX_COLS;
    for (i = 0; i < Len; i++) {
        mLineBuf[i] = GLITCH_CHARS[RngNext() % GLITCH_CHAR_COUNT];
    }
    mLineBuf[Len] = L'\0';
}

// ── Active glitch bars ────────────────────────────────────────────────────────
#define MAX_BARS  8

typedef struct {
    BOOLEAN Active;
    UINTN   Row;
    UINTN   ColStart;
    UINTN   Width;
    UINTN   Attr;
    UINTN   Life;       // frames remaining
} GLITCH_BAR;

STATIC GLITCH_BAR mBars[MAX_BARS];

STATIC VOID
SpawnBar (
    IN UINTN Row,
    IN UINTN ColStart,
    IN UINTN Width,
    IN UINTN Attr,
    IN UINTN Life
    )
{
    UINTN i;
    for (i = 0; i < MAX_BARS; i++) {
        if (!mBars[i].Active) {
            mBars[i].Active   = TRUE;
            mBars[i].Row      = Row;
            mBars[i].ColStart = ColStart;
            mBars[i].Width    = Width;
            mBars[i].Attr     = Attr;
            mBars[i].Life     = Life;
            return;
        }
    }
    // All slots full — evict oldest (slot 0) and reuse
    mBars[0].Row      = Row;
    mBars[0].ColStart = ColStart;
    mBars[0].Width    = Width;
    mBars[0].Attr     = Attr;
    mBars[0].Life     = Life;
}

// ── Draw one glitch frame ─────────────────────────────────────────────────────

STATIC VOID
DrawGlitchFrame (
    IN UINTN FrameIdx
    )
{
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Con = gST->ConOut;
    UINTN TitleRow, MottoRow, TitleCol, MottoCol;
    UINTN Intensity;
    UINTN NewBars, i;

    TitleRow = mNumRows / 2 - 1;
    MottoRow = TitleRow + 1;
    TitleCol = (mNumCols > TITLE_LEN) ? (mNumCols - TITLE_LEN) / 2 : 0;
    MottoCol = (mNumCols > MOTTO_LEN) ? (mNumCols - MOTTO_LEN) / 2 : 0;

    // ── 1. Clear screen to black (single firmware call) ───────────────────────
    Con->SetAttribute(Con, ATTR_BLANK);
    Con->ClearScreen(Con);

    // ── 2. Decide intensity for this frame ────────────────────────────────────
    //   0-1 = quiet,  2-6 = normal,  7-9 = heavy
    Intensity = RngNext() % 10;

    if      (Intensity < 2) NewBars = RngNext() % 2;           // 0-1
    else if (Intensity < 7) NewBars = 1 + RngNext() % 3;       // 1-3
    else                    NewBars = 3 + RngNext() % 4;       // 3-6

    for (i = 0; i < NewBars; i++) {
        UINTN Row      = RngRange(0, (UINT32)(mNumRows - 1));
        UINTN Width    = RngRange(4, (UINT32)mNumCols);
        UINTN ColStart = (Width < mNumCols) ? RngRange(0, (UINT32)(mNumCols - Width)) : 0;
        UINTN Attr     = GLITCH_COLORS[RngNext() % GLITCH_COLOR_COUNT];
        UINTN Life     = RngRange(1, 3);
        SpawnBar(Row, ColStart, Width, Attr, Life);
    }

    // ── 3. Draw + age active bars ─────────────────────────────────────────────
    for (i = 0; i < MAX_BARS; i++) {
        UINTN W, C, MaxW;

        if (!mBars[i].Active) continue;

        // Avoid writing to the very last cell (would cause auto-scroll)
        MaxW = (mBars[i].Row == mNumRows - 1) ? mNumCols - 1 : mNumCols;
        C = mBars[i].ColStart;
        W = mBars[i].Width;
        if (C >= MaxW)              { mBars[i].Active = FALSE; continue; }
        if (C + W > MaxW)           { W = MaxW - C; }
        if (W == 0)                 { mBars[i].Active = FALSE; continue; }

        FillGlitchStr(W);
        Con->SetCursorPosition(Con, C, mBars[i].Row);
        Con->SetAttribute(Con, mBars[i].Attr);
        Con->OutputString(Con, mLineBuf);

        if (mBars[i].Life > 0) mBars[i].Life--;
        if (mBars[i].Life == 0) mBars[i].Active = FALSE;
    }

    // ── 4. Scatter noise on heavy frames ─────────────────────────────────────
    if (Intensity >= 7) {
        UINTN Scatter = RngRange(4, 20);
        for (i = 0; i < Scatter; i++) {
            UINTN R  = RngRange(0, (UINT32)(mNumRows - 1));
            UINTN C2 = RngRange(0, (UINT32)(mNumCols - 2));
            mLineBuf[0] = GLITCH_CHARS[RngNext() % GLITCH_CHAR_COUNT];
            mLineBuf[1] = L'\0';
            Con->SetCursorPosition(Con, C2, R);
            Con->SetAttribute(Con, GLITCH_COLORS[RngNext() % GLITCH_COLOR_COUNT]);
            Con->OutputString(Con, mLineBuf);
        }
    }

    // ── 5. Title — occasionally corrupted, otherwise steady shimmer ───────────
    {
        BOOLEAN Corrupt = (Intensity >= 8) && ((RngNext() % 3) == 0);

        Con->SetCursorPosition(Con, TitleCol, TitleRow);

        if (Corrupt) {
            // Replace a few chars with random glitch chars
            CHAR16 Buf[TITLE_LEN + 1];
            UINTN  j;
            for (j = 0; j < TITLE_LEN; j++) {
                Buf[j] = ((RngNext() % 5) == 0)
                         ? GLITCH_CHARS[RngNext() % GLITCH_CHAR_COUNT]
                         : TITLE[j];
            }
            Buf[TITLE_LEN] = L'\0';
            Con->SetAttribute(Con, GLITCH_COLORS[RngNext() % GLITCH_COLOR_COUNT]);
            Con->OutputString(Con, Buf);
        } else {
            // Slow shimmer: white → light-green every 4 frames
            UINTN TAttr = ((FrameIdx / 4) & 1)
                          ? ATTR_TITLE
                          : EFI_TEXT_ATTR(EFI_LIGHTGREEN, EFI_BACKGROUND_BLACK);
            Con->SetAttribute(Con, TAttr);
            Con->OutputString(Con, (CHAR16 *)TITLE);
        }
    }

    // ── 6. Motto — always steady ──────────────────────────────────────────────
    Con->SetCursorPosition(Con, MottoCol, MottoRow);
    Con->SetAttribute(Con, ATTR_MOTTO);
    Con->OutputString(Con, (CHAR16 *)MOTTO);
}

// ── Public entry point ────────────────────────────────────────────────────────

VOID
GraphicsPlayAnimation (
    IN UINTN DurationMs
    )
{
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Con = gST->ConOut;
    UINTN TotalFrames, FrameIdx, i;
    UINTN Cols = 0, Rows = 0;

    if (Con == NULL) {
        gBS->Stall(DurationMs * 1000);
        return;
    }

    Con->QueryMode(Con, Con->Mode->Mode, &Cols, &Rows);
    if (Cols < 10 || Rows < 5) {
        gBS->Stall(DurationMs * 1000);
        return;
    }

    mNumCols = (Cols < MAX_COLS) ? Cols : MAX_COLS;
    mNumRows = (Rows < MAX_ROWS) ? Rows : MAX_ROWS;

    // Clear bar state
    mRng = 1337;
    for (i = 0; i < MAX_BARS; i++) {
        mBars[i].Active = FALSE;
    }

    Con->EnableCursor(Con, FALSE);

    TotalFrames = DurationMs / FRAME_MS;
    if (TotalFrames == 0) TotalFrames = 1;

    for (FrameIdx = 0; FrameIdx < TotalFrames; FrameIdx++) {
        DrawGlitchFrame(FrameIdx);
        gBS->Stall(FRAME_MS * 1000);
    }

    // Restore
    Con->SetAttribute(Con, EFI_TEXT_ATTR(EFI_LIGHTGRAY, EFI_BACKGROUND_BLACK));
    Con->ClearScreen(Con);
    Con->EnableCursor(Con, TRUE);
}
