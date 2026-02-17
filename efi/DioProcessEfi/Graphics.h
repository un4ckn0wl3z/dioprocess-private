/** @file
  Graphics module for UEFI boot animation.

  Provides GOP (Graphics Output Protocol) access for displaying animated
  boot screens. Uses pre-converted BGRA32 frame data from Animation.h.

  Copyright (c) 2024, DioProcess. All rights reserved.
**/

#ifndef GRAPHICS_H_
#define GRAPHICS_H_

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

/**
  Initialize graphics subsystem by locating GOP.

  @retval EFI_SUCCESS           GOP located successfully.
  @retval EFI_NOT_FOUND         GOP not available (text-only console).
**/
EFI_STATUS
GraphicsInit(
    VOID
    );

/**
  Check if graphics mode is available.

  @retval TRUE   GOP was initialized successfully.
  @retval FALSE  Graphics not available, use text fallback.
**/
BOOLEAN
GraphicsIsAvailable(
    VOID
    );

/**
  Get the current screen resolution.

  @param[out] Width   Horizontal resolution in pixels.
  @param[out] Height  Vertical resolution in pixels.

  @retval EFI_SUCCESS           Resolution returned.
  @retval EFI_NOT_READY         GOP not initialized.
**/
EFI_STATUS
GraphicsGetResolution(
    OUT UINTN *Width,
    OUT UINTN *Height
    );

/**
  Clear the entire screen to black.

  @retval EFI_SUCCESS   Screen cleared.
  @retval EFI_NOT_READY GOP not initialized.
**/
EFI_STATUS
GraphicsClearScreen(
    VOID
    );

/**
  Draw a BGRA32 image buffer to the screen.

  @param[in] Buffer       Pointer to BGRA32 pixel data.
  @param[in] Width        Image width in pixels.
  @param[in] Height       Image height in pixels.
  @param[in] DestX        Destination X coordinate on screen.
  @param[in] DestY        Destination Y coordinate on screen.

  @retval EFI_SUCCESS     Image drawn successfully.
  @retval EFI_NOT_READY   GOP not initialized.
**/
EFI_STATUS
GraphicsDrawImage(
    IN CONST UINT8 *Buffer,
    IN UINTN        Width,
    IN UINTN        Height,
    IN UINTN        DestX,
    IN UINTN        DestY
    );

/**
  Play the embedded animation for the specified duration.

  Loops through animation frames from Animation.h, respecting per-frame
  delays. Animation is centered on screen. If total animation time is
  less than DurationMs, it loops. If graphics unavailable, does nothing.

  @param[in] DurationMs   Total animation duration in milliseconds.
**/
VOID
GraphicsPlayAnimation(
    IN UINTN DurationMs
    );

#endif // GRAPHICS_H_
