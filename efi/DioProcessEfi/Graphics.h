/** @file
  Text-mode Matrix rain animation for UEFI boot screen.

  Drives gST->ConOut (EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL) directly.
  No GOP, no pixel buffers, no Animation.h — the EFI binary stays tiny.

  Copyright (c) 2024, DioProcess. All rights reserved.
**/

#ifndef GRAPHICS_H_
#define GRAPHICS_H_

#include <Uefi.h>

/**
  Play the Matrix rain boot animation for the specified duration.

  Uses the UEFI text console (gST->ConOut) to render falling green
  characters with "DAMNED SOFTWARE" and motto overlaid in the centre.
  Hides the cursor during playback and restores it afterwards.

  @param[in] DurationMs   Total animation duration in milliseconds.
**/
VOID
GraphicsPlayAnimation(
    IN UINTN DurationMs
    );

#endif // GRAPHICS_H_
