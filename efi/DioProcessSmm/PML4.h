/** @file
  DioProcess SMM — Page table structures for address translation.
**/

#ifndef _DIOPROCESS_SMM_PML4_H_
#define _DIOPROCESS_SMM_PML4_H_

#include <Uefi.h>

#pragma pack(push, 1)

typedef union _PML4E {
    struct {
        UINT64 Present : 1;
        UINT64 ReadWrite : 1;
        UINT64 UserSupervisor : 1;
        UINT64 PageWriteThrough : 1;
        UINT64 PageCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Ignored1 : 1;
        UINT64 Reserved1 : 2;
        UINT64 Avl : 3;
        UINT64 Pfn : 40;
        UINT64 Ignored2 : 11;
        UINT64 NoExecute : 1;
    } Bits;
    UINT64 Value;
} PML4E, *PPML4E;

typedef union _PDPE {
    struct {
        UINT64 Present : 1;
        UINT64 ReadWrite : 1;
        UINT64 UserSupervisor : 1;
        UINT64 PageWriteThrough : 1;
        UINT64 PageCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Size : 1;
        UINT64 Global : 1;
        UINT64 Avl : 3;
        UINT64 Pfn : 40;
        UINT64 Ignored2 : 11;
        UINT64 NoExecute : 1;
    } Bits;
    UINT64 Value;
} PDPE, *PPDPE;

typedef union _PDE {
    struct {
        UINT64 Present : 1;
        UINT64 ReadWrite : 1;
        UINT64 UserSupervisor : 1;
        UINT64 PageWriteThrough : 1;
        UINT64 PageCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Size : 1;
        UINT64 Global : 1;
        UINT64 Avl : 3;
        UINT64 Pfn : 40;
        UINT64 Ignored2 : 11;
        UINT64 NoExecute : 1;
    } Bits;
    UINT64 Value;
} PDE, *PPDE;

typedef union _PTE {
    struct {
        UINT64 Present : 1;
        UINT64 ReadWrite : 1;
        UINT64 UserSupervisor : 1;
        UINT64 PageWriteThrough : 1;
        UINT64 PageCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Pat : 1;
        UINT64 Global : 1;
        UINT64 Avl : 3;
        UINT64 Pfn : 40;
        UINT64 Ignored2 : 11;
        UINT64 NoExecute : 1;
    } Bits;
    UINT64 Value;
} PTE, *PPTE;

#pragma pack(pop)

#endif
