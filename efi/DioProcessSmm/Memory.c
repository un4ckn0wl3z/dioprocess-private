/** @file
  DioProcess SMM — Memory operations implementation.
  Based on Deadwing Memory.c.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/CpuLib.h>

#include "Globals.h"
#include "PML4.h"
#include "Defs.h"
#include "Serial.h"

#define CR0_WP    BIT16
#define CR0_PG    BIT31
#define CR4_PSE   BIT4
#define CR4_PAE   BIT5
#define EFER_LMA  BIT8

#define EFI_PAGE_1GB BASE_1GB
#define EFI_PAGE_2MB BASE_2MB
#define EFI_PAGE_4KB BASE_4KB

#define IA32_AMD64_EFER 0xC0000080

VOID
EFIAPI
PhysMemCpy(
    IN VOID   *Dest,
    IN VOID   *Src,
    IN UINT32  Len
    )
{
    for (UINT8 *D = Dest, *S = Src; Len--; *D++ = *S++);
}

BOOLEAN
EFIAPI
MemCheckPagingEnabled(
    VOID
    )
{
    UINT64 Cr0 = AsmReadCr0();
    if (!(Cr0 & CR0_PG)) {
        SerialPrint("[ SMM ] PG bit is not enabled\r\n");
        return FALSE;
    }

    UINT64 Cr4 = AsmReadCr4();
    if (!(Cr4 & CR4_PAE)) {
        if (Cr4 & CR4_PSE) {
            SerialPrint("[ SMM ] 4MB pages enabled, exiting from translation process\r\n");
            return FALSE;
        }
    }

    UINT64 Efer = AsmReadMsr64(IA32_AMD64_EFER);
    if (!(Efer & EFER_LMA)) {
        SerialPrint("[ SMM ] LMA bit is not set\r\n");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
EFIAPI
MemRemapAddress(
    IN  UINT64                          OldAddress,
    IN  UINT64                          NewAddress,
    IN  UINT64                          SmmDir,
    OUT DIOPROCESS_PAGE_TRANSLATION_SIZE *PageSize
    )
{
    SmmDir &= 0xFFFFFFFFFFFFF000;

    PML4E Pml4;
    Pml4.Value = *(UINT64 *)(sizeof(UINT64) * ((OldAddress >> 39) & 0x1FF) + SmmDir);
    if (!Pml4.Bits.Present)
        return FALSE;

    UINT64 Cr0;
    PPDPE Pdpe = (PPDPE)((Pml4.Bits.Pfn << EFI_PAGE_SHIFT) + ((OldAddress >> 30) & 0x1FF) * sizeof(UINT64));
    if (Pdpe->Bits.Present) {
        if (Pdpe->Bits.Size) {
            if (PageSize)
                *PageSize = EDioprocessPage1Gb;

            Cr0 = AsmReadCr0();
            AsmWriteCr0(Cr0 & ~CR0_WP);
            Pdpe->Bits.Pfn = ((NewAddress & ~(EFI_PAGE_1GB - 1)) >> EFI_PAGE_SHIFT);
            AsmWriteCr0(Cr0);
            CpuFlushTlb();
            return TRUE;
        }
    } else {
        return FALSE;
    }

    PPDE Pde = (PPDE)((Pdpe->Bits.Pfn << EFI_PAGE_SHIFT) + ((OldAddress >> 21) & 0x1FF) * sizeof(UINT64));
    if (Pde->Bits.Present) {
        if (Pde->Bits.Size) {
            if (PageSize)
                *PageSize = EDioprocessPage2Mb;

            Cr0 = AsmReadCr0();
            AsmWriteCr0(Cr0 & ~CR0_WP);
            Pde->Bits.Pfn = ((NewAddress & ~(EFI_PAGE_2MB - 1)) >> EFI_PAGE_SHIFT);
            AsmWriteCr0(Cr0);
            CpuFlushTlb();
            return TRUE;
        }
    } else {
        return FALSE;
    }

    PPTE Pte = (PPTE)((Pde->Bits.Pfn << EFI_PAGE_SHIFT) + ((OldAddress >> 12) & 0x1FF) * sizeof(UINT64));
    if (Pte->Bits.Present) {
        if (PageSize)
            *PageSize = EDioprocessPage4Kb;

        Cr0 = AsmReadCr0();
        AsmWriteCr0(Cr0 & ~CR0_WP);
        Pte->Bits.Pfn = ((NewAddress & ~(EFI_PAGE_4KB - 1)) >> EFI_PAGE_SHIFT);
        AsmWriteCr0(Cr0);
        CpuFlushTlb();
        return TRUE;
    }

    return FALSE;
}

VOID
EFIAPI
MemRestoreSmramMappings(
    VOID
    )
{
    UINT64 SmmDir = AsmReadCr3() & 0xFFFFFFFFFFFFF000ULL;
    MemRemapAddress(gRemapPage, gRemapPage, SmmDir, NULL);
}

UINT64
EFIAPI
MemTranslateVirtualToPhys(
    IN VOID   *Address,
    IN UINT64  Dir
    )
{
    UINT64 TargetAddress;
    UINT64 ReadAddress;

    Dir &= 0xFFFFFFFFFFFFF000ULL;
    UINT64 SmmDir = AsmReadCr3() & 0xFFFFFFFFFFFFF000ULL;

    PML4E Pml4;
    UINT8 PageSize = EDioprocessPage4Kb;
    if (MemRemapAddress(gRemapPage, Dir, SmmDir, &PageSize)) {
        TargetAddress = gRemapPage;

        if (PageSize == EDioprocessPage1Gb) {
            TargetAddress += Dir & 0x3FFFFFF;
        } else if (PageSize == EDioprocessPage2Mb) {
            TargetAddress += Dir & 0x1FFFFF;
        } else {
            TargetAddress += Dir & 0xFFF;
        }

        Pml4.Value = *(UINT64 *)(TargetAddress + (((UINT64)Address >> 39) & 0x1FF) * sizeof(UINT64));
        MemRestoreSmramMappings();
    } else {
        SerialPrint("[ SMM ] Unable to remap PML4\r\n");
        return 0;
    }

    PDPE Pdpe;
    if (Pml4.Bits.Present) {
        ReadAddress = Pml4.Bits.Pfn << EFI_PAGE_SHIFT;
        if (MemRemapAddress(gRemapPage, ReadAddress, SmmDir, &PageSize)) {
            TargetAddress = gRemapPage;

            if (PageSize == EDioprocessPage1Gb) {
                TargetAddress += ReadAddress & 0x3FFFFFF;
            } else if (PageSize == EDioprocessPage2Mb) {
                TargetAddress += ReadAddress & 0x1FFFFF;
            } else {
                TargetAddress += ReadAddress & 0xFFF;
            }

            Pdpe.Value = *(UINT64 *)(TargetAddress + (((UINT64)Address >> 30) & 0x1FF) * sizeof(UINT64));
            MemRestoreSmramMappings();
        } else {
            SerialPrint("[ SMM ] Unable to remap PDPE\r\n");
            return 0;
        }
    } else {
        SerialPrint("[ SMM ] PML4 is not present for current virtual address\r\n");
        return 0;
    }

    PDE Pde;
    if (Pdpe.Bits.Present) {
        if (Pdpe.Bits.Size)
            return ((Pdpe.Bits.Pfn << EFI_PAGE_SHIFT) + ((UINT64)Address & 0x3FFFFFF));

        ReadAddress = Pdpe.Bits.Pfn << EFI_PAGE_SHIFT;
        if (MemRemapAddress(gRemapPage, ReadAddress, SmmDir, &PageSize)) {
            TargetAddress = gRemapPage;

            if (PageSize == EDioprocessPage1Gb) {
                TargetAddress += ReadAddress & 0x3FFFFFF;
            } else if (PageSize == EDioprocessPage2Mb) {
                TargetAddress += ReadAddress & 0x1FFFFF;
            } else {
                TargetAddress += ReadAddress & 0xFFF;
            }

            Pde.Value = *(UINT64 *)(TargetAddress + (((UINT64)Address >> 21) & 0x1FF) * sizeof(UINT64));
            MemRestoreSmramMappings();
        } else {
            SerialPrint("[ SMM ] Unable to remap PDE\r\n");
            return 0;
        }
    } else {
        SerialPrint("[ SMM ] PDPE is not present for current virtual address\r\n");
        return 0;
    }

    PTE Pte;
    if (Pde.Bits.Present) {
        if (Pde.Bits.Size)
            return ((Pde.Bits.Pfn << EFI_PAGE_SHIFT) + ((UINT64)Address & 0x1FFFFF));

        ReadAddress = Pde.Bits.Pfn << EFI_PAGE_SHIFT;
        if (MemRemapAddress(gRemapPage, ReadAddress, SmmDir, &PageSize)) {
            TargetAddress = gRemapPage;

            if (PageSize == EDioprocessPage2Mb) {
                TargetAddress += ReadAddress & 0x1FFFFF;
            } else {
                TargetAddress += ReadAddress & 0xFFF;
            }

            Pte.Value = *(UINT64 *)(TargetAddress + (((UINT64)Address >> 12) & 0x1FF) * sizeof(UINT64));
            MemRestoreSmramMappings();
        } else {
            SerialPrint("[ SMM ] Unable to remap PTE\r\n");
            return 0;
        }
    } else {
        SerialPrint("[ SMM ] PDE is not present for current virtual address\r\n");
        return 0;
    }

    if (Pte.Bits.Present)
        return ((Pte.Bits.Pfn << EFI_PAGE_SHIFT) + ((UINT64)Address & 0xFFF));
    else
        SerialPrint("[ SMM ] PTE is not present for current virtual address\r\n");

    return 0;
}

UINT64
EFIAPI
MemProcessOutsideSmramPhysMemory(
    IN UINT64 PhysAddress
    )
{
    UINT8 PageSize = EDioprocessPage4Kb;
    UINT64 RemapedMemory = gRemapPage;
    UINT64 SmmDir = AsmReadCr3();
    if (MemRemapAddress(gRemapPage, PhysAddress, SmmDir, &PageSize)) {
        if (PageSize == EDioprocessPage1Gb) {
            RemapedMemory += PhysAddress & 0x3FFFFFF;
        } else if (PageSize == EDioprocessPage2Mb) {
            RemapedMemory += PhysAddress & 0x1FFFFF;
        } else {
            RemapedMemory += PhysAddress & 0xFFF;
        }
    } else {
        RemapedMemory = 0;
    }

    return RemapedMemory;
}

UINT64
EFIAPI
MemMapVirtualAddress(
    IN  VOID    *VirtualAddress,
    IN  UINT64   DirBase,
    OUT VOID   **UnmappedAddress
    )
{
    UINT64 TranslatedAddress;
    UINT64 PhysRemaped;

    if (!VirtualAddress || !DirBase)
        return 0;

    PhysRemaped = 0;

    if (!MemCheckPagingEnabled())
        return 0;

    TranslatedAddress = MemTranslateVirtualToPhys(VirtualAddress, DirBase);
    if (TranslatedAddress != 0) {
        PhysRemaped = MemProcessOutsideSmramPhysMemory(TranslatedAddress);
        if (PhysRemaped == 0)
            return 0;
    }

    if (UnmappedAddress)
        *UnmappedAddress = (VOID *)TranslatedAddress;

    return PhysRemaped;
}
