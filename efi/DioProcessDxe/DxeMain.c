/** @file
  DioProcess DXE — Main entry point.
  Based on Deadwing DeadwingDxe/DxeMain.c.

  This is the DXE runtime driver that sets up communication with the SMM driver.
  It allocates a communication buffer and exposes the API to the kernel driver
  via an NVRAM variable.
**/

#include <Uefi.h>
#include <Base.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MmCommunication2.h>
#include <Guid/EventGroup.h>

#include "Defs.h"
#include "Globals.h"
#include "Utils.h"
#include "Serial.h"

#define EFI_OBLIGATORY_PTR 0x0
#define DIOPROCESS_COMMUNICATE_HEADER_SIZE (OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data))

EFI_MM_COMMUNICATION2_PROTOCOL *gMmCommunicate2 = NULL;
VOID                           *gCommBuf = NULL;
VOID                           *gPhysCommBuf = NULL;
UINTN                           gCommSize = 0;
EFI_EVENT                       gExitBs = NULL;
EFI_EVENT                       gGoneVirtual = NULL;
EFI_EVENT                       gRegNotify = NULL;

EFI_STATUS
EFIAPI
SetupCommunicationBuffer(
    IN PDIOPROCESS_COMMUNICATION CommunicationPacket,
    IN UINTN                     DataSize
    )
{
    if (DataSize > gCommSize)
        return EFI_INVALID_PARAMETER;

    EFI_MM_COMMUNICATE_HEADER *CommHeader = (EFI_MM_COMMUNICATE_HEADER *)gCommBuf;

    CopyMemory(&CommHeader->HeaderGuid, &gDioProcessSmiHandlerGuid, sizeof(EFI_GUID));
    CopyMemory(&CommHeader->Data, CommunicationPacket, sizeof(DIOPROCESS_COMMUNICATION));
    CommHeader->MessageLength = gCommSize;

    return EFI_SUCCESS;
}

PDIOPROCESS_COMMUNICATION
EFIAPI
DioProcessSmmCommunicate(
    VOID
    )
{
    UINTN CommSize = gCommSize;
    EFI_STATUS Status = gMmCommunicate2->Communicate(gMmCommunicate2, gPhysCommBuf, gCommBuf, &CommSize);
    if (EFI_ERROR(Status))
        return NULL;

    EFI_MM_COMMUNICATE_HEADER *CommHeader = (EFI_MM_COMMUNICATE_HEADER *)gCommBuf;
    PDIOPROCESS_COMMUNICATION CommPacket = (PDIOPROCESS_COMMUNICATION)CommHeader->Data;

    return CommPacket;
}

EFI_STATUS
EFIAPI
FireSmi(
    IN UINT64 Command
    )
{
    DIOPROCESS_COMMUNICATION CommPacket;
    CommPacket.Command = (UINT32)Command;
    CommPacket.SmiRetStatus = EFI_COMPROMISED_DATA;

    SetupCommunicationBuffer(&CommPacket, sizeof(CommPacket));

    PDIOPROCESS_COMMUNICATION OutputPacket = DioProcessSmmCommunicate();
    if (OutputPacket == NULL)
        return EFI_ABORTED;

    gBS->SetMem(gCommBuf, gCommSize, 0);

    return OutputPacket->SmiRetStatus;
}

VOID
EFIAPI
DioProcessDxeGoneVirtual(
    IN EFI_EVENT  Event,
    IN VOID      *Context
    )
{
    SerialPrint("[ DXE ] Virtual address change callback\r\n");

    VOID *VirtualBuf = gPhysCommBuf;
    VOID *SetupCommBufFunc = (VOID *)SetupCommunicationBuffer;
    VOID *DioProcessSmmCommFunc = (VOID *)DioProcessSmmCommunicate;

    gRT->ConvertPointer(EFI_OBLIGATORY_PTR, (VOID **)&gMmCommunicate2);
    gRT->ConvertPointer(EFI_OBLIGATORY_PTR, (VOID **)&VirtualBuf);
    gRT->ConvertPointer(EFI_OBLIGATORY_PTR, (VOID **)&SetupCommBufFunc);
    gRT->ConvertPointer(EFI_OBLIGATORY_PTR, (VOID **)&DioProcessSmmCommFunc);

    gCommBuf = VirtualBuf;

    DIOPROCESS_TRANSFER Transfer = { 0 };
    Transfer.Buffer.CommBufPhys = gPhysCommBuf;
    Transfer.Buffer.CommBufVirtual = gCommBuf;
    Transfer.Buffer.BufSize = gCommSize;
    Transfer.API.SetupBufFunction = SetupCommBufFunc;
    Transfer.API.SmmCommunicateFunction = DioProcessSmmCommFunc;

    EFI_STATUS Status = gRT->SetVariable(
        L"DioProcessSmmTransfer",
        &gDioProcessTransferVarGuid,
        (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS),
        sizeof(DIOPROCESS_TRANSFER),
        &Transfer
    );
    if (EFI_ERROR(Status))
        SerialPrint("[ DXE ] Unable to publish transfer packet\r\n");

    SerialPrint("[ DXE ] Transfering to RT phase\r\n");

    gGoneVirtual = NULL;
}

VOID
EFIAPI
DioProcessBeforeExitBootServices(
    IN EFI_EVENT  Event,
    IN VOID      *Context
    )
{
    SerialPrint("[ DXE ] Checking if SMI handler is available\r\n");

    EFI_STATUS Status = FireSmi(CMD_DIOPROCESS_PING_SMI);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Unable to ping SMI handler\r\n");
        gBS->CloseEvent(gGoneVirtual);
    }

    gBS->CloseEvent(gExitBs);
}

VOID
EFIAPI
MmCommProtocolRegistrationCallback(
    IN EFI_EVENT  Event,
    IN VOID      *Context
    )
{
    SerialPrint("[ DXE ] EFI_MM_COMMUNICATION2_PROTOCOL registration callback\r\n");

    EFI_STATUS Status = gBS->LocateProtocol(&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&gMmCommunicate2);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Unable to locate EFI_MM_COMMUNICATION2_PROTOCOL\r\n");
        gBS->CloseEvent(gGoneVirtual);
        gBS->FreePool(gCommBuf);
    } else {
        SerialPrint("[ DXE ] EFI_MM_COMMUNICATION2_PROTOCOL discovered\r\n");
    }

    gBS->CloseEvent(gRegNotify);
}

EFI_STATUS
EFIAPI
DioProcessDxeMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    SerialPrint("=[ DioProcess DXE ]=\r\n");

    gCommSize = sizeof(DIOPROCESS_COMMUNICATION) + DIOPROCESS_COMMUNICATE_HEADER_SIZE;

    EFI_STATUS Status = gBS->AllocatePool(EfiRuntimeServicesData, gCommSize, &gPhysCommBuf);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Unable to allocate communication buffer\r\n");
        return Status;
    }

    gBS->SetMem(gPhysCommBuf, gCommSize, 0);
    gCommBuf = gPhysCommBuf;

    VOID *Registration;
    BOOLEAN IsAwaitingForRegistration = FALSE;
    Status = gBS->LocateProtocol(&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&gMmCommunicate2);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Waiting for EFI_MM_COMMUNICATION2_PROTOCOL...\r\n");

        Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, MmCommProtocolRegistrationCallback, NULL, &gRegNotify);
        if (EFI_ERROR(Status)) {
            SerialPrint("[ DXE ] Unable to create registration callback\r\n");
            gBS->FreePool(gCommBuf);
            return Status;
        }

        Status = gBS->RegisterProtocolNotify(&gEfiMmCommunication2ProtocolGuid, gRegNotify, &Registration);
        if (EFI_ERROR(Status)) {
            SerialPrint("[ DXE ] Unable to register protocol notify\r\n");
            gBS->CloseEvent(gRegNotify);
            gBS->FreePool(gCommBuf);
            return Status;
        }

        IsAwaitingForRegistration = TRUE;
    }

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DioProcessBeforeExitBootServices, NULL, &gEfiEventBeforeExitBootServicesGuid, &gExitBs);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Cannot create ExitBootServices callback\r\n");
        gBS->FreePool(gCommBuf);
        if (IsAwaitingForRegistration)
            gBS->CloseEvent(gRegNotify);
        return Status;
    }

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DioProcessDxeGoneVirtual, NULL, &gEfiEventVirtualAddressChangeGuid, &gGoneVirtual);
    if (EFI_ERROR(Status)) {
        SerialPrint("[ DXE ] Cannot create virtual address change callback\r\n");
        gBS->FreePool(gCommBuf);
        gBS->CloseEvent(gExitBs);
        if (IsAwaitingForRegistration)
            gBS->CloseEvent(gRegNotify);
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
    gBS = SystemTable->BootServices;
    gRT = SystemTable->RuntimeServices;

    return DioProcessDxeMain(ImageHandle, SystemTable);
}
