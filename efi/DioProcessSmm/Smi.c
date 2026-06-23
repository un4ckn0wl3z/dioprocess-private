/** @file
  DioProcess SMM — SMI handler implementation.
  Based on Deadwing Smi.c.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/SmmMemLib.h>
#include <Protocol/MmCommunication2.h>

#include "Globals.h"
#include "Defs.h"
#include "Serial.h"
#include "Commands.h"

#define DIOPROCESS_COMMUNICATE_HEADER_SIZE (OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data))

STATIC CONST EFI_GUID gDioProcessSmiHandlerGuid = { 0x2BFADA50, 0xAF38, 0x49A1, { 0x85, 0x34, 0x08, 0xF6, 0xAE, 0x1B, 0x4C, 0x96 } };

EFI_STATUS
EFIAPI
DioProcessSmiHandler(
    IN           EFI_HANDLE  DispatchHandle,
    IN     CONST VOID       *Context        OPTIONAL,
    IN OUT       VOID       *CommBuffer     OPTIONAL,
    IN OUT       UINTN      *CommBufferSize OPTIONAL
    )
{
    UINTN TempSize;
    UINTN PayloadSize;
    PDIOPROCESS_COMMUNICATION SmiCommCtx;

    SerialPrint("[ SMM ] Hit DioProcess SMI handler\r\n");

    if (CommBuffer == NULL || CommBufferSize == 0) {
        SerialPrint("[ SMM ] Invalid communication buffer\r\n");
        return EFI_SUCCESS;
    }

    TempSize = *CommBufferSize;
    PayloadSize = TempSize - DIOPROCESS_COMMUNICATE_HEADER_SIZE;

    if (!SmmIsBufferOutsideSmmValid((UINTN)CommBuffer, PayloadSize)) {
        SerialPrint("[ SMM ] Communication buffer overlaps SMRAM!\r\n");
        return EFI_SUCCESS;
    }

    SmiCommCtx = (PDIOPROCESS_COMMUNICATION)CommBuffer;
    SpeculationBarrier();

    SmiCommCtx->SmiRetStatus = CmdMainHandler(SmiCommCtx);

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SmiRegisterHandler(
    VOID
    )
{
    EFI_HANDLE Handle;
    EFI_STATUS Status = gSmst2->SmiHandlerRegister(DioProcessSmiHandler, &gDioProcessSmiHandlerGuid, &Handle);
    if (EFI_ERROR(Status))
        SerialPrint("[ SMM ] Unable to register SMI handler\r\n");

    return Status;
}
