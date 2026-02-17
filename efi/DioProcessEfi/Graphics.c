/** @file
  Graphics module implementation for UEFI boot animation.

  Uses GOP (Graphics Output Protocol) to display animated boot screens.
  Falls back gracefully if GOP is unavailable (legacy BIOS, text console).

  Copyright (c) 2024, DioProcess. All rights reserved.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/GraphicsOutput.h>

#include "Graphics.h"
#include "Animation.h"

//
// Global GOP instance
//
STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL *mGop = NULL;
STATIC BOOLEAN mGraphicsInitialized = FALSE;
STATIC UINTN mScreenWidth = 0;
STATIC UINTN mScreenHeight = 0;

//
// Double buffer for tear-free animation
//
STATIC EFI_GRAPHICS_OUTPUT_BLT_PIXEL *mBackBuffer = NULL;
STATIC UINTN mBackBufferSize = 0;

EFI_STATUS
GraphicsInit(
    VOID
    )
{
    EFI_STATUS Status;

    if (mGraphicsInitialized) {
        return EFI_SUCCESS;
    }

    //
    // Locate GOP
    //
    Status = gBS->LocateProtocol(
        &gEfiGraphicsOutputProtocolGuid,
        NULL,
        (VOID **)&mGop
    );

    if (EFI_ERROR(Status)) {
        mGop = NULL;
        mGraphicsInitialized = FALSE;
        return EFI_NOT_FOUND;
    }

    //
    // Get current mode info
    //
    if (mGop->Mode != NULL && mGop->Mode->Info != NULL) {
        mScreenWidth = mGop->Mode->Info->HorizontalResolution;
        mScreenHeight = mGop->Mode->Info->VerticalResolution;
    } else {
        // Fallback to common resolution
        mScreenWidth = 1024;
        mScreenHeight = 768;
    }

    //
    // Allocate back buffer for double buffering (tear-free animation)
    //
    mBackBufferSize = mScreenWidth * mScreenHeight * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    mBackBuffer = AllocatePool(mBackBufferSize);
    if (mBackBuffer == NULL) {
        // Continue without double buffering
        mBackBuffer = NULL;
        mBackBufferSize = 0;
    }

    mGraphicsInitialized = TRUE;
    return EFI_SUCCESS;
}

BOOLEAN
GraphicsIsAvailable(
    VOID
    )
{
    return mGraphicsInitialized && (mGop != NULL);
}

EFI_STATUS
GraphicsGetResolution(
    OUT UINTN *Width,
    OUT UINTN *Height
    )
{
    if (!GraphicsIsAvailable()) {
        return EFI_NOT_READY;
    }

    if (Width != NULL) {
        *Width = mScreenWidth;
    }
    if (Height != NULL) {
        *Height = mScreenHeight;
    }

    return EFI_SUCCESS;
}

EFI_STATUS
GraphicsClearScreen(
    VOID
    )
{
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL Black = {0, 0, 0, 0};

    if (!GraphicsIsAvailable()) {
        return EFI_NOT_READY;
    }

    //
    // Fill entire screen with black
    //
    return mGop->Blt(
        mGop,
        &Black,
        EfiBltVideoFill,
        0, 0,           // Source X, Y (ignored for fill)
        0, 0,           // Dest X, Y
        mScreenWidth,
        mScreenHeight,
        0               // Delta (stride, 0 = use Width)
    );
}

EFI_STATUS
GraphicsDrawImage(
    IN CONST UINT8 *Buffer,
    IN UINTN        Width,
    IN UINTN        Height,
    IN UINTN        DestX,
    IN UINTN        DestY
    )
{
    if (!GraphicsIsAvailable()) {
        return EFI_NOT_READY;
    }

    if (Buffer == NULL || Width == 0 || Height == 0) {
        return EFI_INVALID_PARAMETER;
    }

    //
    // Clip to screen bounds
    //
    if (DestX >= mScreenWidth || DestY >= mScreenHeight) {
        return EFI_SUCCESS;  // Completely off-screen
    }

    UINTN DrawWidth = Width;
    UINTN DrawHeight = Height;

    if (DestX + DrawWidth > mScreenWidth) {
        DrawWidth = mScreenWidth - DestX;
    }
    if (DestY + DrawHeight > mScreenHeight) {
        DrawHeight = mScreenHeight - DestY;
    }

    //
    // Buffer is BGRA32, which matches EFI_GRAPHICS_OUTPUT_BLT_PIXEL layout
    // (Blue, Green, Red, Reserved) when using PixelBlueGreenRedReserved8BitPerColor
    //
    // For maximum compatibility, we use EfiBltBufferToVideo which handles
    // pixel format conversion if needed.
    //
    return mGop->Blt(
        mGop,
        (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)Buffer,
        EfiBltBufferToVideo,
        0, 0,                    // Source X, Y in buffer
        DestX, DestY,            // Dest X, Y on screen
        DrawWidth,
        DrawHeight,
        Width * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)  // Source stride
    );
}

VOID
GraphicsPlayAnimation(
    IN UINTN DurationMs
    )
{
    UINTN FrameIndex;
    UINTN ElapsedMs;
    UINTN FrameDelay;
    UINTN CenterX;
    UINTN CenterY;
    UINTN X, Y;
    UINTN SrcX, SrcY;
    UINTN DrawWidth, DrawHeight;
    EFI_STATUS Status;
    CONST UINT8 *FrameData;
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Pixel;

    //
    // Initialize graphics if not already done
    //
    Status = GraphicsInit();
    if (EFI_ERROR(Status)) {
        // Graphics not available, fall back to delay only
        gBS->Stall(DurationMs * 1000);
        return;
    }

    //
    // If no back buffer, fall back to direct drawing (may tear)
    //
    if (mBackBuffer == NULL) {
        GraphicsClearScreen();
        
        if (mScreenWidth > ANIMATION_WIDTH) {
            CenterX = (mScreenWidth - ANIMATION_WIDTH) / 2;
        } else {
            CenterX = 0;
        }
        if (mScreenHeight > ANIMATION_HEIGHT) {
            CenterY = (mScreenHeight - ANIMATION_HEIGHT) / 2;
        } else {
            CenterY = 0;
        }
        
        ElapsedMs = 0;
        FrameIndex = 0;
        while (ElapsedMs < DurationMs) {
            GraphicsDrawImage(AnimationFrames[FrameIndex], ANIMATION_WIDTH, ANIMATION_HEIGHT, CenterX, CenterY);
            FrameDelay = AnimationDelays[FrameIndex];
            if (ElapsedMs + FrameDelay > DurationMs) {
                FrameDelay = DurationMs - ElapsedMs;
            }
            gBS->Stall(FrameDelay * 1000);
            ElapsedMs += FrameDelay;
            FrameIndex = (FrameIndex + 1) % ANIMATION_FRAME_COUNT;
        }
        return;
    }

    //
    // Calculate center position for animation
    //
    if (mScreenWidth > ANIMATION_WIDTH) {
        CenterX = (mScreenWidth - ANIMATION_WIDTH) / 2;
    } else {
        CenterX = 0;
    }

    if (mScreenHeight > ANIMATION_HEIGHT) {
        CenterY = (mScreenHeight - ANIMATION_HEIGHT) / 2;
    } else {
        CenterY = 0;
    }

    //
    // Calculate actual draw dimensions (clip to screen)
    //
    DrawWidth = ANIMATION_WIDTH;
    DrawHeight = ANIMATION_HEIGHT;
    if (CenterX + DrawWidth > mScreenWidth) {
        DrawWidth = mScreenWidth - CenterX;
    }
    if (CenterY + DrawHeight > mScreenHeight) {
        DrawHeight = mScreenHeight - CenterY;
    }

    //
    // Play animation loop with double buffering
    //
    ElapsedMs = 0;
    FrameIndex = 0;

    while (ElapsedMs < DurationMs) {
        //
        // Clear back buffer to black
        //
        SetMem(mBackBuffer, mBackBufferSize, 0);

        //
        // Copy animation frame to center of back buffer
        //
        FrameData = AnimationFrames[FrameIndex];
        for (Y = 0; Y < DrawHeight; Y++) {
            for (X = 0; X < DrawWidth; X++) {
                SrcX = X;
                SrcY = Y;
                
                // Source pixel from animation frame (BGRA32)
                UINTN SrcOffset = (SrcY * ANIMATION_WIDTH + SrcX) * 4;
                
                // Destination pixel in back buffer
                Pixel = &mBackBuffer[(CenterY + Y) * mScreenWidth + (CenterX + X)];
                
                Pixel->Blue     = FrameData[SrcOffset + 0];
                Pixel->Green    = FrameData[SrcOffset + 1];
                Pixel->Red      = FrameData[SrcOffset + 2];
                Pixel->Reserved = 0;
            }
        }

        //
        // Blit entire back buffer to screen (single operation = no tearing)
        //
        mGop->Blt(
            mGop,
            mBackBuffer,
            EfiBltBufferToVideo,
            0, 0,           // Source X, Y
            0, 0,           // Dest X, Y
            mScreenWidth,
            mScreenHeight,
            0               // Delta
        );

        //
        // Wait for frame delay
        //
        FrameDelay = AnimationDelays[FrameIndex];
        if (ElapsedMs + FrameDelay > DurationMs) {
            FrameDelay = DurationMs - ElapsedMs;
        }

        gBS->Stall(FrameDelay * 1000);  // Stall takes microseconds
        ElapsedMs += FrameDelay;

        //
        // Advance to next frame (loop)
        //
        FrameIndex++;
        if (FrameIndex >= ANIMATION_FRAME_COUNT) {
            FrameIndex = 0;
        }
    }

    //
    // Free back buffer
    //
    if (mBackBuffer != NULL) {
        FreePool(mBackBuffer);
        mBackBuffer = NULL;
        mBackBufferSize = 0;
    }
}
