/** @file
  DioProcess SMM — Main entry point.
  Based on Deadwing SmmMain.c.

  This is the SMM driver that handles SMI requests from the kernel driver.
  It provides Ring -2 memory operations.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SmmBase2.h>

#include "Globals.h"
#include "Defs.h"
#include "Smi.h"
#include "Serial.h"

EFI_SMM_SYSTEM_TABLE2  *gSmst2 = NULL;
EFI_PHYSICAL_ADDRESS    gRemapPage = 0;

EFI_STATUS
EFIAPI
InitializeSmmContext(
    VOID
    )
{
    EFI_STATUS Status;

    Status = SmiRegisterHandler();
    if (!EFI_ERROR(Status)) {
        Status = gSmst2->SmmAllocatePages(AllocateAnyPages, EfiRuntimeServicesData, 1, &gRemapPage);
        if (EFI_ERROR(Status)) {
            SerialPrint("[ SMM ] Unable to allocate remap page\r\n");
            return Status;
        }

        gBS->SetMem((VOID *)gRemapPage, EFI_PAGE_SIZE, 0);
    } else {
        SerialPrint("[ SMM ] Unable to register SMI handler\r\n");
    }

    return Status;
}

EFI_STATUS
EFIAPI
DioProcessSmmMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    SerialPrint("=[ DioProcess SMM ]=\r\n");
    SerialPrint("=[ Ring -2 Memory Operations ]=\r\n");

    EFI_SMM_BASE2_PROTOCOL *Smm2;
    EFI_STATUS Status = gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, (VOID **)&Smm2);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ SMM ] Unable to locate SmmBase protocol\r\n");
        return Status;
    }

    BOOLEAN SmmSanityCheck;
    Smm2->InSmm(Smm2, &SmmSanityCheck);
    if (SmmSanityCheck) {
        SerialPrint("[ SMM ] SMM driver invoked by SMM IPL, initializing...\r\n");

        Status = Smm2->GetSmstLocation(Smm2, &gSmst2);
        if (EFI_ERROR(Status)) {
            SerialPrint("[ SMM ] Unable to get SMST\r\n");
            return Status;
        }

        Status = InitializeSmmContext();
        if (EFI_ERROR(Status))
            SerialPrint("[ SMM ] Unable to initialize context\r\n");
        else
            SerialPrint("[ SMM ] SMM driver has been initialized\r\n");
    } else {
        SerialPrint("[ SMM ] SMM driver started under DXE environment\r\n");
        return EFI_ACCESS_DENIED;
    }

    return Status;
}

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE ImageHandle
    )
{
    return EFI_ACCESS_DENIED;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    gST = SystemTable;
    gBS = gST->BootServices;
    gRT = gST->RuntimeServices;

    return DioProcessSmmMain(ImageHandle, SystemTable);
}
