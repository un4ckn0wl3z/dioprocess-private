/** @file
  DioProcess DXE — Utility functions.
**/

#ifndef _DIOPROCESS_DXE_UTILS_H_
#define _DIOPROCESS_DXE_UTILS_H_

#include <Uefi.h>

VOID
EFIAPI
CopyMemory(
    IN OUT VOID       *Dest,
    IN     CONST VOID *Src,
    IN     UINTN       Len
    );

#endif
