/** @file
  GOP-based boot animation for UEFI boot screen.

  Uses EFI_GRAPHICS_OUTPUT_PROTOCOL for consistent rendering across
  real hardware. Falls back to text console if GOP unavailable.

  Copyright (c) 2024, DioProcess. All rights reserved.
**/

#ifndef GRAPHICS_H_
#define GRAPHICS_H_

#include <Uefi.h>

/**
  Play the glitch boot animation for the specified duration.

  Uses GOP (Graphics Output Protocol) for direct framebuffer access.
  Falls back to simple text display if GOP is not available.

  @param[in] DurationMs   Total animation duration in milliseconds.
**/
VOID
GraphicsPlayAnimation(
    IN UINTN DurationMs
    );

#endif // GRAPHICS_H_
