/** @file
  DioProcess DXE — Utility functions implementation.
**/

#include <Uefi.h>

#include "Utils.h"

VOID
EFIAPI
CopyMemory(
    IN OUT VOID       *Dest,
    IN     CONST VOID *Src,
    IN     UINTN       Len
    )
{
    UINT8 *D = (UINT8 *)Dest;
    CONST UINT8 *S = (CONST UINT8 *)Src;
    while (Len--) {
        *D++ = *S++;
    }
}
