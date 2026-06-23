/** @file
  DioProcess SMM — Memory operations.
**/

#ifndef _DIOPROCESS_SMM_MEMORY_H_
#define _DIOPROCESS_SMM_MEMORY_H_

#include <Uefi.h>
#include "Defs.h"

VOID
EFIAPI
PhysMemCpy(
    IN VOID   *Dest,
    IN VOID   *Src,
    IN UINT32  Len
    );

BOOLEAN
EFIAPI
MemCheckPagingEnabled(
    VOID
    );

BOOLEAN
EFIAPI
MemRemapAddress(
    IN  UINT64                          OldAddress,
    IN  UINT64                          NewAddress,
    IN  UINT64                          SmmDir,
    OUT DIOPROCESS_PAGE_TRANSLATION_SIZE *PageSize
    );

VOID
EFIAPI
MemRestoreSmramMappings(
    VOID
    );

UINT64
EFIAPI
MemTranslateVirtualToPhys(
    IN VOID   *Address,
    IN UINT64  Dir
    );

UINT64
EFIAPI
MemProcessOutsideSmramPhysMemory(
    IN UINT64 PhysAddress
    );

UINT64
EFIAPI
MemMapVirtualAddress(
    IN  VOID    *VirtualAddress,
    IN  UINT64   DirBase,
    OUT VOID   **UnmappedAddress
    );

#endif
